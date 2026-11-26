package admin

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/pairing"
	"github.com/all-notify/server/internal/store"
)

//go:embed web/*
var webFS embed.FS

const (
	sessionCookieName     = "an_admin"
	csrfHeaderName        = "X-AllNotify-Admin"
	defaultSessionTTL     = 30 * time.Minute
	loginMaxFailures      = 5
	loginWindow           = 15 * time.Minute
	maxAdminJSONBodyBytes = 16 * 1024
	kcvSettingKey         = "kcv"

	cspHeader = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

var kcvHexPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Config struct {
	SessionTTL time.Duration
	TrustProxy bool
	Now        func() time.Time
	Logger     *slog.Logger
}

type Handler struct {
	store      *store.Store
	hub        *hub.Hub
	pairing    *pairing.Service
	sessionTTL time.Duration
	trustProxy bool
	now        func() time.Time
	logger     *slog.Logger
	loginLimit *RateLimiter
	// Serializes argon2id (64 MiB each) so concurrent login/password bursts cannot
	// bypass the 5-failure rate limit or OOM a small 512 MB VPS.
	authMu sync.Mutex
}

func NewHandler(st *store.Store, h *hub.Hub, ps *pairing.Service, cfg Config) *Handler {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Handler{
		store:      st,
		hub:        h,
		pairing:    ps,
		sessionTTL: cfg.SessionTTL,
		trustProxy: cfg.TrustProxy,
		now:        cfg.Now,
		logger:     cfg.Logger,
		loginLimit: NewRateLimiter(loginMaxFailures, loginWindow, cfg.Now),
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setSecurityHeaders(w)
			fn(w, r)
		})
	}

	mux.Handle("GET /admin", wrap(h.handleIndex))
	mux.Handle("GET /admin/", wrap(h.handleIndex))
	mux.Handle("GET /admin/assets/{file}", wrap(h.handleAsset))

	mux.Handle("POST /admin/api/login", wrap(h.handleLogin))
	mux.Handle("POST /admin/api/logout", wrap(h.handleLogout))
	mux.Handle("GET /admin/api/session", wrap(h.handleSession))
	mux.Handle("POST /admin/api/password", wrap(h.handleChangePassword))

	mux.Handle("GET /admin/api/kcv", wrap(h.requireAdmin(false, h.handleGetKCV)))
	mux.Handle("PUT /admin/api/kcv", wrap(h.requireAdmin(true, h.handlePutKCV)))

	mux.Handle("GET /admin/api/devices", wrap(h.requireAdmin(false, h.handleListDevices)))
	mux.Handle("PATCH /admin/api/devices/{id}", wrap(h.requireAdmin(true, h.handlePatchDevice)))
	mux.Handle("POST /admin/api/devices/{id}/revoke", wrap(h.requireAdmin(true, h.handleRevokeDevice)))

	mux.Handle("POST /admin/api/pairing-codes", wrap(h.requireAdmin(true, h.handleCreatePairingCode)))
	mux.Handle("GET /admin/api/pairing-codes", wrap(h.requireAdmin(false, h.handleListPairingCodes)))
	mux.Handle("DELETE /admin/api/pairing-codes/{id}", wrap(h.requireAdmin(true, h.handleDeletePairingCode)))
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", cspHeader)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxAdminJSONBodyBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("trailing json data")
	}
	return nil
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" && r.URL.Path != "/admin/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	var contentType string
	switch name {
	case "admin.css":
		contentType = "text/css; charset=utf-8"
	case "admin.js", "qrcode.min.js":
		contentType = "application/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *Handler) checkCSRF(r *http.Request) bool {
	if r.Header.Get(csrfHeaderName) != "1" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	ou, err := url.Parse(origin)
	if err != nil || ou.Host == "" {
		return false
	}
	if !strings.EqualFold(ou.Host, r.Host) {
		return false
	}
	if r.TLS != nil || (h.trustProxy && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")) {
		return strings.EqualFold(ou.Scheme, "https")
	}
	// Behind a TLS-terminating reverse proxy with TRUST_PROXY=false, r.TLS is nil while browser Origin is https.
	return strings.EqualFold(ou.Scheme, "https") || strings.EqualFold(ou.Scheme, "http")
}

func (h *Handler) shouldSetSecureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if h.trustProxy && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	host := r.Host
	if hPart, _, err := net.SplitHostPort(host); err == nil {
		host = hPart
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	return host != "localhost" && host != "127.0.0.1" && host != "::1"
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, r *http.Request, rawToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    rawToken,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   h.shouldSetSecureCookie(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.sessionTTL.Seconds()),
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure:   h.shouldSetSecureCookie(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func (h *Handler) authenticateSession(w http.ResponseWriter, r *http.Request) (sessionHash string, cred *store.AdminCredential, ok bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return "", nil, false
	}
	raw := c.Value
	tokHash := auth.HashToken(raw)
	nowMs := h.now().UnixMilli()
	newExpMs := nowMs + h.sessionTTL.Milliseconds()
	valid, err := h.store.TouchAdminSession(r.Context(), tokHash, nowMs, newExpMs)
	if err != nil || !valid {
		return "", nil, false
	}
	cred, err = h.store.GetAdminCredential(r.Context())
	if err != nil {
		return "", nil, false
	}
	// Refresh idle cookie lifetime on use.
	h.setSessionCookie(w, r, raw)
	return tokHash, cred, true
}

func (h *Handler) requireAdmin(stateChanging bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if stateChanging && !h.checkCSRF(r) {
			writeError(w, http.StatusForbidden, "CSRF_REJECTED", "missing or invalid CSRF header or Origin")
			return
		}
		_, cred, ok := h.authenticateSession(w, r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "admin login required")
			return
		}
		if cred.MustChange {
			writeError(w, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "initial admin password must be changed before proceeding")
			return
		}
		next(w, r)
	}
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		writeError(w, http.StatusForbidden, "CSRF_REJECTED", "missing or invalid CSRF header or Origin")
		return
	}
	ip := ClientIP(r, h.trustProxy)
	if h.loginLimit.IsLimited(ip) {
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many failed login attempts; try again later")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req); err != nil || req.Password == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "password is required")
		return
	}

	h.authMu.Lock()
	if h.loginLimit.IsLimited(ip) {
		h.authMu.Unlock()
		writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many failed login attempts; try again later")
		return
	}

	cred, err := h.store.GetAdminCredential(r.Context())
	if err != nil {
		h.authMu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "ADMIN_UNINITIALIZED", "admin credentials are not initialized")
		return
	}
	if !VerifyPassword(req.Password, cred.PasswordHash) {
		h.loginLimit.Record(ip)
		h.authMu.Unlock()
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid password")
		return
	}
	h.loginLimit.Reset(ip)
	h.authMu.Unlock()

	rawSess, sessHash, err := auth.GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create session")
		return
	}
	nowMs := h.now().UnixMilli()
	if err := h.store.CreateAdminSession(r.Context(), store.AdminSession{
		TokenHash: sessHash,
		CreatedAt: nowMs,
		ExpiresAt: nowMs + h.sessionTTL.Milliseconds(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save session")
		return
	}

	h.setSessionCookie(w, r, rawSess)
	_, kcvErr := h.store.GetSetting(r.Context(), kcvSettingKey)
	writeJSON(w, http.StatusOK, map[string]any{
		"logged_in":            true,
		"must_change_password": cred.MustChange,
		"kcv_set":              kcvErr == nil,
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		writeError(w, http.StatusForbidden, "CSRF_REJECTED", "missing or invalid CSRF header or Origin")
		return
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
		_ = h.store.DeleteAdminSession(r.Context(), auth.HashToken(c.Value))
	}
	h.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleSession(w http.ResponseWriter, r *http.Request) {
	_, cred, ok := h.authenticateSession(w, r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]bool{
			"logged_in":            false,
			"must_change_password": false,
			"kcv_set":              false,
		})
		return
	}
	_, kcvErr := h.store.GetSetting(r.Context(), kcvSettingKey)
	writeJSON(w, http.StatusOK, map[string]bool{
		"logged_in":            true,
		"must_change_password": cred.MustChange,
		"kcv_set":              kcvErr == nil,
	})
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(r) {
		writeError(w, http.StatusForbidden, "CSRF_REJECTED", "missing or invalid CSRF header or Origin")
		return
	}
	sessHash, cred, ok := h.authenticateSession(w, r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "admin login required")
		return
	}

	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body")
		return
	}
	h.authMu.Lock()
	okCurrent := VerifyPassword(req.Current, cred.PasswordHash)
	if !okCurrent {
		h.authMu.Unlock()
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "current password is incorrect")
		return
	}
	if utf8.RuneCountInString(req.New) < MinPasswordLen {
		h.authMu.Unlock()
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "new password must be at least 12 characters")
		return
	}
	if req.New == req.Current {
		h.authMu.Unlock()
		writeError(w, http.StatusBadRequest, "PASSWORD_UNCHANGED", "new password must differ from current password")
		return
	}

	newHash, err := HashPassword(req.New)
	h.authMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to hash password")
		return
	}
	if err := h.store.SetAdminPassword(r.Context(), newHash, false, h.now().UnixMilli(), sessHash); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"must_change_password": false,
	})
}

func (h *Handler) handleGetKCV(w http.ResponseWriter, r *http.Request) {
	val, err := h.store.GetSetting(r.Context(), kcvSettingKey)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"kcv": nil, "set": false})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read kcv")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kcv": val, "set": true})
}

func (h *Handler) handlePutKCV(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KCV string `json:"kcv"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body")
		return
	}
	kcv := strings.ToLower(strings.TrimSpace(req.KCV))
	if !kcvHexPattern.MatchString(kcv) {
		writeError(w, http.StatusBadRequest, "INVALID_KCV", "kcv must be 32 hex characters")
		return
	}
	if err := h.store.SetSettingIfUnset(r.Context(), kcvSettingKey, kcv); err != nil {
		if errors.Is(err, store.ErrAlreadySet) {
			writeError(w, http.StatusConflict, "KCV_ALREADY_SET", "group key check value is already set")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save kcv")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kcv": kcv, "set": true})
}

type adminDeviceDTO struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	CanAddDevices bool   `json:"can_add_devices"`
	Online        bool   `json:"online"`
	LastSeen      *int64 `json:"last_seen"`
	CreatedAt     int64  `json:"created_at"`
	RevokedAt     *int64 `json:"revoked_at"`
}

func (h *Handler) toDeviceDTO(d store.Device) adminDeviceDTO {
	online := false
	if h.hub != nil && d.RevokedAt == nil {
		online = h.hub.IsOnline(d.ID)
	}
	return adminDeviceDTO{
		ID:            d.ID,
		Name:          d.Name,
		Platform:      d.Platform,
		CanAddDevices: d.CanAddDevices,
		Online:        online,
		LastSeen:      d.LastSeen,
		CreatedAt:     d.CreatedAt,
		RevokedAt:     d.RevokedAt,
	}
}

func (h *Handler) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.store.ListDevices(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list devices")
		return
	}
	out := make([]adminDeviceDTO, 0, len(devices))
	for _, d := range devices {
		out = append(out, h.toDeviceDTO(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "device id is required")
		return
	}
	var req struct {
		Name          *string `json:"name"`
		CanAddDevices *bool   `json:"can_add_devices"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body")
		return
	}
	if req.Name == nil && req.CanAddDevices == nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "at least one field (name or can_add_devices) is required")
		return
	}
	var cleanName *string
	if req.Name != nil {
		n, err := pairing.ValidateName(*req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		cleanName = &n
	}
	updated, err := h.store.UpdateDevice(r.Context(), id, cleanName, req.CanAddDevices)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
			return
		}
		if errors.Is(err, store.ErrDeviceRevoked) {
			writeError(w, http.StatusConflict, "DEVICE_REVOKED", "cannot modify a revoked device")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update device")
		return
	}
	writeJSON(w, http.StatusOK, h.toDeviceDTO(*updated))
}

func (h *Handler) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "device id is required")
		return
	}
	ok, err := h.store.RevokeDevice(r.Context(), id, h.now().UnixMilli())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to revoke device")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found or already revoked")
		return
	}
	if h.hub != nil {
		h.hub.DisconnectDevice(id, "revoked")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleCreatePairingCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		Platform      string `json:"platform"`
		CanAddDevices bool   `json:"can_add_devices"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body")
		return
	}
	created, err := h.pairing.Create(r.Context(), pairing.CreateRequest{
		Name:          req.Name,
		Platform:      req.Platform,
		CanAddDevices: req.CanAddDevices,
		CreatedBy:     "admin",
	})
	if err != nil {
		if errors.Is(err, pairing.ErrInvalidInput) {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create pairing code")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) handleListPairingCodes(w http.ResponseWriter, r *http.Request) {
	list, err := h.pairing.List(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list pairing codes")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) handleDeletePairingCode(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	err := h.pairing.Cancel(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, pairing.ErrCodeNotFound):
			writeError(w, http.StatusNotFound, "CODE_NOT_FOUND", "pairing code not found")
		case errors.Is(err, pairing.ErrCodeExpiredOrUsed):
			writeError(w, http.StatusGone, "CODE_EXPIRED_OR_USED", "pairing code is no longer pending")
		default:
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to cancel pairing code")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
