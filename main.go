// kitty-vps-relay is a narrowly-scoped WebSocket relay for Kitty Bots.
// It accepts a browser tunnel only from MooMoo origins, authenticates the
// tunnel, and can connect only to a configured MooMoo WSS host suffix. It is
// intentionally not a general-purpose proxy.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	openTimeout          = 10 * time.Second
	targetConnectTimeout = 12 * time.Second
	maxOpenMessageBytes  = 4 * 1024
	maxRelayPayloadBytes = 256 * 1024
	maxTunnelCap         = 100
)

type config struct {
	addr                  string
	staticAccessKey       string
	tokenSigningSecret    string
	defaultMaxTunnels     int
	allowedTargetSuffixes []string
	extraAllowedOrigins   map[string]struct{}
	partnerSecret         []byte
	partnerUpstream       string
}

// relayTokenClaims is the one-time, short-lived browser credential created by
// the Kitty account service. It is deliberately separate from the partner
// TOTP: the browser is allowed to receive this scoped ticket, but never the
// partner secret or a TOTP derived from it. New account-service tickets use
// millisecond Unix timestamps; the older bridge format used seconds, so both
// are accepted during a safe migration.
type relayTokenClaims struct {
	Type        string `json:"typ"`
	Audience   string `json:"aud"`
	Subject    string `json:"sub"`
	Nonce      string `json:"nonce"`
	ExpiresAt  int64  `json:"exp"`
	MaxTunnels int    `json:"maxTunnels"`
}

type relayPrincipal struct {
	identity      string
	maxTunnels    int
	ticketID      string
	ticketExpires time.Time
}

type relayService struct {
	config   config
	logger   *slog.Logger
	upgrader websocket.Upgrader
	dialer   websocket.Dialer

	mu              sync.Mutex
	active          map[string]int
	consumedTickets map[string]time.Time
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("invalid relay configuration", "error", err)
		os.Exit(1)
	}

	service := &relayService{
		config: cfg,
		logger: slog.Default(),
		active: make(map[string]int),
		consumedTickets: make(map[string]time.Time),
		dialer: websocket.Dialer{
			HandshakeTimeout: targetConnectTimeout,
			EnableCompression: false,
			Proxy:             http.ProxyFromEnvironment,
		},
	}
	service.upgrader = websocket.Upgrader{
		ReadBufferSize:    8 * 1024,
		WriteBufferSize:   8 * 1024,
		EnableCompression: false,
		CheckOrigin: func(request *http.Request) bool {
			return service.originAllowed(request.Header.Get("Origin"))
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", service.handleHealth)
	mux.HandleFunc("GET /relay", service.handleRelay)
	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		service.logger.Info(
			"Kitty VPS relay listening",
			"address", cfg.addr,
			"defaultMaxTunnels", cfg.defaultMaxTunnels,
			"partnerMode", cfg.partnerUpstream != "",
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			service.logger.Error("relay server stopped", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		service.logger.Error("relay shutdown timed out", "error", err)
	}
}

func loadConfig() (config, error) {
	staticKey := strings.TrimSpace(os.Getenv("RELAY_ACCESS_KEY"))
	tokenSecret := strings.TrimSpace(os.Getenv("RELAY_TOKEN_SIGNING_SECRET"))
	if staticKey == "" && tokenSecret == "" {
		return config{}, errors.New("set RELAY_ACCESS_KEY or RELAY_TOKEN_SIGNING_SECRET to a random value of at least 32 characters")
	}
	if staticKey != "" && len(staticKey) < 32 {
		return config{}, errors.New("RELAY_ACCESS_KEY must be at least 32 characters")
	}
	if tokenSecret != "" && len(tokenSecret) < 32 {
		return config{}, errors.New("RELAY_TOKEN_SIGNING_SECRET must be at least 32 characters")
	}
	partnerSecret, partnerUpstream, err := loadPartnerConfig()
	if err != nil {
		return config{}, err
	}
	defaultMaxTunnels := 2
	if partnerUpstream != "" {
		defaultMaxTunnels = 65
	}
	maxTunnels, err := boundedPositiveEnv("RELAY_MAX_TUNNELS", defaultMaxTunnels, maxTunnelCap)
	if err != nil {
		return config{}, err
	}
	targetSuffixes := splitLowerEnv("RELAY_TARGET_SUFFIXES", "moomoo.io")
	if len(targetSuffixes) == 0 {
		return config{}, errors.New("RELAY_TARGET_SUFFIXES must include at least one hostname suffix")
	}
	extraOrigins := make(map[string]struct{})
	for _, origin := range strings.Split(os.Getenv("RELAY_ALLOWED_ORIGINS"), ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			extraOrigins[origin] = struct{}{}
		}
	}
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "10000"
	}
	bindHost := strings.TrimSpace(os.Getenv("RELAY_BIND_HOST"))
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	return config{
		addr:                  net.JoinHostPort(bindHost, port),
		staticAccessKey:       staticKey,
		tokenSigningSecret:    tokenSecret,
		defaultMaxTunnels:     maxTunnels,
		allowedTargetSuffixes: targetSuffixes,
		extraAllowedOrigins:   extraOrigins,
		partnerSecret:         partnerSecret,
		partnerUpstream:       partnerUpstream,
	}, nil
}

func loadPartnerConfig() ([]byte, string, error) {
	rawSecret := strings.TrimSpace(os.Getenv("PARTNER_SECRET_B64"))
	if rawSecret == "" {
		return nil, "", nil
	}
	secret, err := base64.StdEncoding.DecodeString(rawSecret)
	if err != nil {
		secret, err = base64.RawStdEncoding.DecodeString(rawSecret)
	}
	if err != nil || len(secret) < 32 {
		return nil, "", errors.New("PARTNER_SECRET_B64 must be a valid base64 secret of at least 32 bytes")
	}
	rawUpstream := strings.TrimSpace(os.Getenv("PARTNER_UPSTREAM"))
	if rawUpstream == "" {
		rawUpstream = "wss://relay.rrelayservers.win/ws"
	}
	upstream, err := url.Parse(rawUpstream)
	if err != nil || upstream.Scheme != "wss" || upstream.Hostname() == "" || upstream.User != nil {
		return nil, "", errors.New("PARTNER_UPSTREAM must be a credential-free wss:// URL")
	}
	return secret, upstream.String(), nil
}

func boundedPositiveEnv(name string, fallback, maximum int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("%s must be an integer from 1 to %d", name, maximum)
	}
	return value, nil
}

func splitLowerEnv(name, fallback string) []string {
	raw := os.Getenv(name)
	if strings.TrimSpace(raw) == "" {
		raw = fallback
	}
	values := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		item = strings.Trim(strings.ToLower(strings.TrimSpace(item)), ".")
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(response, request)
	})
}

func (service *relayService) handleHealth(response http.ResponseWriter, _ *http.Request) {
	service.mu.Lock()
	active := 0
	for _, count := range service.active {
		active += count
	}
	service.mu.Unlock()
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"ok":                true,
		"service":           "kitty-vps-relay-go",
		"activeTunnels":     active,
		"defaultMaxTunnels": service.config.defaultMaxTunnels,
		"partnerMode":       service.config.partnerUpstream != "",
	})
}

func (service *relayService) handleRelay(response http.ResponseWriter, request *http.Request) {
	if !service.originAllowed(request.Header.Get("Origin")) {
		http.Error(response, "Origin is not allowed.", http.StatusForbidden)
		return
	}
	// Kitty's normal account-gated route supplies a short-lived `ticket`.
	// Keep `key` as a legacy external-relay fallback, but never use either to
	// transport a partner TOTP or its signing secret.
	credential := request.URL.Query().Get("ticket")
	if credential == "" {
		credential = request.URL.Query().Get("key")
	}
	principal, ok := service.authorize(credential)
	if !ok {
		http.Error(response, "Invalid relay credential.", http.StatusUnauthorized)
		return
	}
	if !service.reserve(principal) {
		http.Error(response, "Relay connection limit reached.", http.StatusTooManyRequests)
		return
	}
	slotHeld := true
	defer func() {
		if slotHeld {
			service.release(principal.identity)
		}
	}()

	client, err := service.upgrader.Upgrade(response, request, nil)
	if err != nil {
		return
	}
	defer client.Close()
	service.relayTunnel(request, client)
}

func (service *relayService) authorize(rawCredential string) (relayPrincipal, bool) {
	if service.config.staticAccessKey != "" && constantTimeEqual(rawCredential, service.config.staticAccessKey) {
		return relayPrincipal{identity: "static", maxTunnels: service.config.defaultMaxTunnels}, true
	}
	if service.config.tokenSigningSecret == "" {
		return relayPrincipal{}, false
	}
	parts := strings.Split(rawCredential, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return relayPrincipal{}, false
	}
	expected := hmac.New(sha256.New, []byte(service.config.tokenSigningSecret))
	_, _ = expected.Write([]byte(parts[0]))
	expectedSignature := expected.Sum(nil)
	providedSignature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || subtle.ConstantTimeCompare(expectedSignature, providedSignature) != 1 {
		return relayPrincipal{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > maxOpenMessageBytes {
		return relayPrincipal{}, false
	}
	var claims relayTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil || strings.TrimSpace(claims.Subject) == "" {
		return relayPrincipal{}, false
	}
	now := time.Now()
	// Kitty account-service tickets use Date.now(), while the original Go
	// bridge format used seconds. Both are finite int64 values, so normalize
	// only values that clearly carry milliseconds.
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if claims.ExpiresAt > 10_000_000_000 {
		expiresAt = time.UnixMilli(claims.ExpiresAt)
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(10*time.Minute)) {
		return relayPrincipal{}, false
	}
	maxTunnels := claims.MaxTunnels
	if maxTunnels < 1 || maxTunnels > maxTunnelCap {
		return relayPrincipal{}, false
	}
	subjectHash := sha256.Sum256([]byte(claims.Subject))
	principal := relayPrincipal{
		identity:      "token:" + base64.RawURLEncoding.EncodeToString(subjectHash[:12]),
		maxTunnels:    maxTunnels,
		ticketExpires: expiresAt,
	}
	// The modern account-service format binds the ticket to this bridge and
	// includes a nonce. Its fingerprint is held only in memory until expiry so
	// a copied URL cannot open another tunnel. This is transient replay
	// protection, not user-data storage.
	if claims.Type == "kitty-bot-relay" && claims.Audience == "kitty-bot-relay" && len(claims.Nonce) >= 16 {
		ticketHash := sha256.Sum256([]byte(rawCredential))
		principal.ticketID = base64.RawURLEncoding.EncodeToString(ticketHash[:])
		return principal, true
	}
	// Compatibility for the previous VPS-only ticket format. New deployments
	// should use the account-service ticket above.
	if claims.Type == "" && claims.Audience == "kitty-vps-relay" {
		return principal, true
	}
	return relayPrincipal{}, false
}

func constantTimeEqual(got, expected string) bool {
	if len(got) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func (service *relayService) reserve(principal relayPrincipal) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	now := time.Now()
	for ticketID, expiresAt := range service.consumedTickets {
		if !expiresAt.After(now) {
			delete(service.consumedTickets, ticketID)
		}
	}
	if principal.ticketID != "" {
		if _, used := service.consumedTickets[principal.ticketID]; used {
			return false
		}
	}
	if service.active[principal.identity] >= principal.maxTunnels {
		return false
	}
	if principal.ticketID != "" {
		service.consumedTickets[principal.ticketID] = principal.ticketExpires
	}
	service.active[principal.identity]++
	return true
}

func (service *relayService) release(identity string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.active[identity] <= 1 {
		delete(service.active, identity)
		return
	}
	service.active[identity]--
}

func (service *relayService) originAllowed(rawOrigin string) bool {
	if _, ok := service.config.extraAllowedOrigins[rawOrigin]; ok {
		return true
	}
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.Scheme != "https" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(origin.Hostname()), ".")
	return host == "moomoo.frvr.com" || host == "moomoo.io" || strings.HasSuffix(host, ".moomoo.io")
}

func (service *relayService) targetAllowed(rawTarget string) (*url.URL, bool) {
	target, err := url.Parse(rawTarget)
	if err != nil || target.Scheme != "wss" || target.User != nil || target.Hostname() == "" {
		return nil, false
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	for _, suffix := range service.config.allowedTargetSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return target, true
		}
	}
	return nil, false
}

func (service *relayService) relayTunnel(request *http.Request, client *websocket.Conn) {
	client.SetReadLimit(maxRelayPayloadBytes)
	client.SetReadDeadline(time.Now().Add(openTimeout))
	messageType, message, err := client.ReadMessage()
	if err != nil || messageType != websocket.TextMessage || len(message) > maxOpenMessageBytes {
		closeWith(client, 4400, "Invalid open request.")
		return
	}
	client.SetReadDeadline(time.Time{})
	var openRequest struct {
		Type   string `json:"type"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal(message, &openRequest); err != nil || openRequest.Type != "open" {
		closeWith(client, 4400, "Invalid open request.")
		return
	}
	target, allowed := service.targetAllowed(openRequest.Target)
	if !allowed {
		closeWith(client, 4403, "Target is not allowed.")
		return
	}

	context, cancel := context.WithTimeout(context.Background(), targetConnectTimeout)
	defer cancel()
	game, targetHost, err := service.dialTarget(context, target, request)
	if err != nil {
		service.logger.Warn("relay target connection failed", "targetHost", target.Hostname(), "error", err.Error())
		closeWith(client, websocket.CloseInternalServerErr, "Relay target connection failed.")
		return
	}
	defer game.Close()
	game.SetReadLimit(maxRelayPayloadBytes)
	if err := client.WriteJSON(map[string]string{"type": "ready"}); err != nil {
		return
	}
	service.logger.Info("relay tunnel opened", "targetHost", targetHost)

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxyMessages(client, game)
		// Closing both ends wakes the opposite copy loop even when it is
		// blocked waiting for an otherwise idle socket. That releases the
		// principal's concurrency slot instead of leaving a ghost tunnel.
		_ = client.Close()
		_ = game.Close()
	}()
	proxyMessages(game, client)
	_ = client.Close()
	_ = game.Close()
	<-done
	service.logger.Info("relay tunnel closed", "targetHost", targetHost)
}

func (service *relayService) dialTarget(
	ctx context.Context,
	target *url.URL,
	request *http.Request,
) (*websocket.Conn, string, error) {
	headers := make(http.Header)
	if userAgent := strings.TrimSpace(request.Header.Get("User-Agent")); userAgent != "" {
		headers.Set("User-Agent", userAgent)
	}
	if service.config.partnerUpstream == "" {
		if origin := request.Header.Get("Origin"); origin != "" {
			headers.Set("Origin", origin)
		}
		connection, _, err := service.dialer.DialContext(ctx, target.String(), headers)
		return connection, target.Hostname(), err
	}

	token, err := service.partnerTOTP()
	if err != nil {
		return nil, target.Hostname(), err
	}
	upstream, err := url.Parse(service.config.partnerUpstream)
	if err != nil {
		return nil, target.Hostname(), err
	}
	query := upstream.Query()
	query.Set("pool", "partner")
	query.Set("token", token)
	query.Set("target", target.String())
	upstream.RawQuery = query.Encode()
	// The partner endpoint authenticates the bridge with the same token in its
	// query and WebSocket subprotocol. Do not relay the browser Origin there:
	// this side is a server-to-server connection, matching the partner bridge.
	dialer := service.dialer
	dialer.Subprotocols = []string{"totp." + token}
	connection, response, err := dialer.DialContext(ctx, upstream.String(), headers)
	if err != nil {
		if response != nil {
			return nil, target.Hostname(), fmt.Errorf("partner relay rejected the connection with HTTP %d", response.StatusCode)
		}
		return nil, target.Hostname(), fmt.Errorf("partner relay connection failed: %w", err)
	}
	return connection, target.Hostname(), nil
}

func (service *relayService) partnerTOTP() (string, error) {
	if len(service.config.partnerSecret) < 32 {
		return "", errors.New("partner relay is not configured")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/300))
	mac := hmac.New(sha256.New, service.config.partnerSecret)
	if _, err := mac.Write(counter[:]); err != nil {
		return "", err
	}
	digest := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(digest[:16]), nil
}

func proxyMessages(destination, source *websocket.Conn) {
	for {
		messageType, message, err := source.ReadMessage()
		if err != nil {
			return
		}
		if err := destination.WriteMessage(messageType, message); err != nil {
			return
		}
	}
}

func closeWith(connection *websocket.Conn, code int, reason string) {
	deadline := time.Now().Add(time.Second)
	_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), deadline)
	_ = connection.Close()
}
