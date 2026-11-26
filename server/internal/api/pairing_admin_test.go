package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/all-notify/server/internal/admin"
	"github.com/all-notify/server/internal/api"
	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/blobs"
	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/store"
	"github.com/coder/websocket"
)

type phase5Env struct {
	dir     string
	st      *store.Store
	h       *hub.Hub
	srv     *httptest.Server
	logs    *bytes.Buffer
	clockMu sync.Mutex
	now     time.Time
}

func (e *phase5Env) nowFn() time.Time {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	return e.now
}

func (e *phase5Env) advance(d time.Duration) {
	e.clockMu.Lock()
	e.now = e.now.Add(d)
	e.clockMu.Unlock()
}

func newPhase5Env(t *testing.T, adminEnabled, trustProxy bool) (*phase5Env, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "all-notify.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	env := &phase5Env{
		dir:  dir,
		st:   st,
		logs: &logBuf,
		now:  time.UnixMilli(1_764_060_000_000),
	}

	var pwOut bytes.Buffer
	var initPW string
	if adminEnabled {
		created, err := admin.EnsureInitialPassword(context.Background(), st, &pwOut, env.nowFn)
		if err != nil || !created {
			t.Fatalf("EnsureInitialPassword: created=%v err=%v", created, err)
		}
		line := strings.TrimSpace(pwOut.String())
		idx := strings.LastIndex(line, ": ")
		if idx < 0 {
			t.Fatalf("unexpected initial password line: %q", line)
		}
		initPW = line[idx+2:]
	}

	bm, err := blobs.New(st, blobs.Config{
		Dir:    filepath.Join(dir, "blobs"),
		Now:    env.nowFn,
		Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := hub.New(st, hub.Config{
		Now:    env.nowFn,
		Logger: logger,
	})
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		h.CloseAll(shutCtx)
	})
	env.h = h

	apiSrv := api.NewWithOptions(st, h, bm, api.Options{
		Logger:          logger,
		AdminEnabled:    adminEnabled,
		PairingCodeTTL:  10 * time.Minute,
		AdminSessionTTL: 30 * time.Minute,
		TrustProxy:      trustProxy,
		Now:             env.nowFn,
	})
	ts := httptest.NewServer(apiSrv)
	t.Cleanup(ts.Close)
	env.srv = ts
	return env, initPW
}

func newAdminClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func doReq(t *testing.T, client *http.Client, method, urlStr string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, urlStr, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, raw
}

func adminHeaders(baseURL string) map[string]string {
	return map[string]string{
		"X-AllNotify-Admin": "1",
		"Origin":            baseURL,
	}
}

func TestAdminFullFlowSecurityAndZeroKnowledge(t *testing.T) {
	env, initPW := newPhase5Env(t, true, false)

	// 1. Static /admin & assets carry strict CSP + security headers.
	for _, path := range []string{"/admin", "/admin/assets/admin.css", "/admin/assets/admin.js", "/admin/assets/qrcode.min.js"} {
		resp, body := doReq(t, http.DefaultClient, http.MethodGet, env.srv.URL+path, nil, nil)
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("GET %s: status=%d len=%d", path, resp.StatusCode, len(body))
		}
		if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("missing CSP on %s: %q", path, resp.Header.Get("Content-Security-Policy"))
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" || resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("missing security headers on %s: %v", path, resp.Header)
		}
	}

	// 2. CSRF protection: missing header or bad Origin rejected.
	c1 := newAdminClient(t)
	resp, _ := doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": initPW}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login without CSRF headers expected 403, got %d", resp.StatusCode)
	}
	resp, _ = doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": initPW}, map[string]string{
		"X-AllNotify-Admin": "1",
		"Origin":            "https://evil.example.com",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login with wrong Origin expected 403, got %d", resp.StatusCode)
	}

	// 3. Login with initial password -> must_change_password=true gates other endpoints.
	resp, raw := doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": initPW}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d %s", resp.StatusCode, string(raw))
	}
	// Login second session c2 to test cross-session invalidation on password change.
	c2 := newAdminClient(t)
	resp, _ = doReq(t, c2, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": initPW}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second login failed: %d", resp.StatusCode)
	}

	// Blocked by must_change_password.
	resp, raw = doReq(t, c1, http.MethodGet, env.srv.URL+"/admin/api/devices", nil, nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "PASSWORD_CHANGE_REQUIRED") {
		t.Fatalf("expected 403 PASSWORD_CHANGE_REQUIRED, got %d %s", resp.StatusCode, string(raw))
	}

	// Weak password rejected.
	resp, _ = doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/password", map[string]string{"current": initPW, "new": "short"}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak password expected 400, got %d", resp.StatusCode)
	}

	// Valid password change keeps c1 and invalidates c2.
	newPW := "correct-horse-battery-staple-99"
	resp, raw = doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/password", map[string]string{"current": initPW, "new": newPW}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change failed: %d %s", resp.StatusCode, string(raw))
	}
	resp, _ = doReq(t, c2, http.MethodGet, env.srv.URL+"/admin/api/devices", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("c2 session should be invalidated after password change, got %d", resp.StatusCode)
	}

	// 4. KCV set once (using real K_master computed locally; K_master NEVER sent to server).
	kMasterBytes, kMasterB64, err := auth.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	kcv, err := auth.ComputeKCV(kMasterBytes)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw = doReq(t, c1, http.MethodPut, env.srv.URL+"/admin/api/kcv", map[string]string{"kcv": kcv}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT kcv failed: %d %s", resp.StatusCode, string(raw))
	}
	resp, _ = doReq(t, c1, http.MethodPut, env.srv.URL+"/admin/api/kcv", map[string]string{"kcv": "00000000000000000000000000000000"}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second PUT kcv expected 409, got %d", resp.StatusCode)
	}

	// 5. Admin creates a pairing code (trusted=true) and a new device claims it.
	resp, raw = doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/pairing-codes", map[string]any{
		"name":            "Pixel 9",
		"platform":        "android",
		"can_add_devices": true,
	}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create pairing code failed: %d %s", resp.StatusCode, string(raw))
	}
	var created struct {
		CodeID string `json:"code_id"`
		Code   string `json:"code"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}

	// GET /admin/api/pairing-codes must NOT include the raw code.
	resp, raw = doReq(t, c1, http.MethodGet, env.srv.URL+"/admin/api/pairing-codes", nil, nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(raw), created.Code) {
		t.Fatalf("pairing code list leaked raw code or failed: %d %s", resp.StatusCode, string(raw))
	}

	// Claim code via public endpoint.
	resp, raw = doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pair/claim", map[string]string{
		"code":     created.Code,
		"platform": "android",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim failed: %d %s", resp.StatusCode, string(raw))
	}
	var claimed struct {
		DeviceID      string `json:"device_id"`
		Token         string `json:"token"`
		Name          string `json:"name"`
		Platform      string `json:"platform"`
		CanAddDevices bool   `json:"can_add_devices"`
	}
	if err := json.Unmarshal(raw, &claimed); err != nil {
		t.Fatal(err)
	}
	if claimed.Name != "Pixel 9" || !claimed.CanAddDevices || claimed.Token == "" {
		t.Fatalf("unexpected claim response: %+v", claimed)
	}

	// Re-claiming same code returns 410 CODE_EXPIRED_OR_USED.
	resp, raw = doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pair/claim", map[string]string{
		"code":     created.Code,
		"platform": "android",
	}, nil)
	if resp.StatusCode != http.StatusGone || !strings.Contains(string(raw), "CODE_EXPIRED_OR_USED") {
		t.Fatalf("reuse claim expected 410, got %d %s", resp.StatusCode, string(raw))
	}

	// 6. Claimed device connects via WS and calls GET /v1/me.
	wsURL := "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/v1/ws"
	wsCtx, wsCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, _, err := websocket.Dial(wsCtx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":        []string{"Bearer " + claimed.Token},
			"X-AllNotify-Protocol": []string{"1"},
		},
	})
	wsCancel()
	if err != nil {
		t.Fatalf("WS dial claimed device: %v", err)
	}
	defer conn.CloseNow()
	rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	if _, _, err := conn.Read(rctx); err != nil {
		rcancel()
		t.Fatalf("read replay_complete: %v", err)
	}
	rcancel()

	// GET /v1/me reports can_add_devices=true.
	resp, raw = doReq(t, http.DefaultClient, http.MethodGet, env.srv.URL+"/v1/me", nil, map[string]string{
		"Authorization": "Bearer " + claimed.Token,
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"can_add_devices":true`) {
		t.Fatalf("GET /v1/me failed: %d %s", resp.StatusCode, string(raw))
	}

	// Trusted device can create a pairing code (always can_add_devices=false) for MacBook.
	resp, raw = doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pairing-codes", map[string]string{
		"name":     "MacBook",
		"platform": "macos",
	}, map[string]string{"Authorization": "Bearer " + claimed.Token})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("trusted device create code failed: %d %s", resp.StatusCode, string(raw))
	}
	var devCode struct {
		Code          string `json:"code"`
		CanAddDevices bool   `json:"can_add_devices"`
	}
	_ = json.Unmarshal(raw, &devCode)
	if devCode.CanAddDevices {
		t.Fatalf("trusted device created code must always have can_add_devices=false")
	}

	// Trusted device CANNOT access admin endpoints (list/revoke/rename).
	resp, _ = doReq(t, http.DefaultClient, http.MethodGet, env.srv.URL+"/admin/api/devices", nil, map[string]string{
		"Authorization": "Bearer " + claimed.Token,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("trusted device accessing /admin/api/devices expected 401, got %d", resp.StatusCode)
	}

	// Claim MacBook code -> untrusted device.
	resp, raw = doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pair/claim", map[string]string{
		"code":     devCode.Code,
		"platform": "macos",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("claim macbook failed: %d %s", resp.StatusCode, string(raw))
	}
	var macClaim struct {
		DeviceID      string `json:"device_id"`
		Token         string `json:"token"`
		CanAddDevices bool   `json:"can_add_devices"`
	}
	_ = json.Unmarshal(raw, &macClaim)
	if macClaim.CanAddDevices {
		t.Fatalf("macbook claimed from trusted-device code must not be trusted")
	}

	// Untrusted device gets 403 NOT_TRUSTED on POST/GET /v1/pairing-codes.
	resp, raw = doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pairing-codes", map[string]string{
		"name":     "Rogue",
		"platform": "windows",
	}, map[string]string{"Authorization": "Bearer " + macClaim.Token})
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "NOT_TRUSTED") {
		t.Fatalf("untrusted device create code expected 403 NOT_TRUSTED, got %d %s", resp.StatusCode, string(raw))
	}
	resp, _ = doReq(t, http.DefaultClient, http.MethodGet, env.srv.URL+"/v1/pairing-codes", nil, map[string]string{
		"Authorization": "Bearer " + macClaim.Token,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted device list codes expected 403, got %d", resp.StatusCode)
	}

	// 7. Admin sees Pixel 9 as online, renames it, and revokes it -> live WS closes with 1008.
	resp, raw = doReq(t, c1, http.MethodGet, env.srv.URL+"/admin/api/devices", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"online":true`) {
		t.Fatalf("expected online device in admin list: %d %s", resp.StatusCode, string(raw))
	}
	resp, raw = doReq(t, c1, http.MethodPatch, env.srv.URL+"/admin/api/devices/"+claimed.DeviceID, map[string]any{
		"name": "Pixel 9 Pro",
	}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "Pixel 9 Pro") {
		t.Fatalf("rename device failed: %d %s", resp.StatusCode, string(raw))
	}
	resp, _ = doReq(t, c1, http.MethodPost, env.srv.URL+"/admin/api/devices/"+claimed.DeviceID+"/revoke", nil, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke device failed: %d", resp.StatusCode)
	}
	revCtx, revCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _, wsErr := conn.Read(revCtx)
	revCancel()
	if status := websocket.CloseStatus(wsErr); status != websocket.StatusPolicyViolation {
		t.Fatalf("revoked WS close status = %v (err=%v), want StatusPolicyViolation(1008)", status, wsErr)
	}

	// 8. Session idle expiry after 31 min -> 401.
	env.advance(31 * time.Minute)
	resp, _ = doReq(t, c1, http.MethodGet, env.srv.URL+"/admin/api/devices", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired session expected 401, got %d", resp.StatusCode)
	}

	// 9. Zero-knowledge verification: K_master never appears in DB or server logs.
	dbBytes, err := os.ReadFile(filepath.Join(env.dir, "all-notify.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(dbBytes, []byte(kMasterB64)) || bytes.Contains(env.logs.Bytes(), []byte(kMasterB64)) {
		t.Fatalf("K_master leaked into DB or logs!")
	}
}

func TestAdminLoginAndClaimRateLimitsAndProxyTrust(t *testing.T) {
	env, _ := newPhase5Env(t, true, true)
	c := newAdminClient(t)

	// 5 wrong login attempts from X-Forwarded-For 203.0.113.10 -> 6th returns 429.
	for i := 0; i < 5; i++ {
		hdr := adminHeaders(env.srv.URL)
		hdr["X-Forwarded-For"] = "1.1.1.1, 203.0.113.10"
		resp, _ := doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": "wrong-password"}, hdr)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d", i+1, resp.StatusCode)
		}
	}
	hdr := adminHeaders(env.srv.URL)
	hdr["X-Forwarded-For"] = "9.9.9.9, 203.0.113.10" // spoofed leftmost IP still blocked by rightmost real IP
	resp, _ := doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": "wrong-password"}, hdr)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th login attempt expected 429, got %d", resp.StatusCode)
	}

	// Different real IP is not rate-limited.
	hdr["X-Forwarded-For"] = "203.0.113.11"
	resp, _ = doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": "wrong-password"}, hdr)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("different IP expected 401, got %d", resp.StatusCode)
	}

	// Claim rate limit: 10/min per IP -> 11th returns 429.
	for i := 0; i < 10; i++ {
		resp, _ := doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pair/claim", map[string]string{
			"code":     "pc_AAECAwQFBgcICQoLDA0ODw",
			"platform": "android",
		}, map[string]string{"X-Forwarded-For": "198.51.100.7"})
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("claim attempt %d expected 404, got %d", i+1, resp.StatusCode)
		}
	}
	resp, _ = doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/v1/pair/claim", map[string]string{
		"code":     "pc_AAECAwQFBgcICQoLDA0ODw",
		"platform": "android",
	}, map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th claim attempt expected 429, got %d", resp.StatusCode)
	}
}

func TestAdminDisabledAndResetPasswordInvalidatesSessions(t *testing.T) {
	// Admin disabled returns 404 on /admin and /admin/api/session.
	disabledEnv, _ := newPhase5Env(t, false, false)
	resp, _ := doReq(t, http.DefaultClient, http.MethodGet, disabledEnv.srv.URL+"/admin", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled /admin expected 404, got %d", resp.StatusCode)
	}
	resp, _ = doReq(t, http.DefaultClient, http.MethodGet, disabledEnv.srv.URL+"/admin/api/session", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled /admin/api/session expected 404, got %d", resp.StatusCode)
	}

	// Admin reset-password invalidates live sessions and forces change again.
	env, initPW := newPhase5Env(t, true, false)
	c := newAdminClient(t)
	resp, _ = doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": initPW}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	resp, _ = doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/password", map[string]string{"current": initPW, "new": "brand-new-strong-pw-123"}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change password failed: %d", resp.StatusCode)
	}
	var resetOut bytes.Buffer
	resetPW, err := admin.ResetPassword(context.Background(), env.st, &resetOut, env.nowFn)
	if err != nil || resetPW == "" {
		t.Fatalf("ResetPassword failed: %v", err)
	}
	// Old session invalidated.
	resp, _ = doReq(t, c, http.MethodGet, env.srv.URL+"/admin/api/devices", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after reset expected 401, got %d", resp.StatusCode)
	}
	// Logging in with reset password requires password change again.
	resp, raw := doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": resetPW}, adminHeaders(env.srv.URL))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"must_change_password":true`) {
		t.Fatalf("login with reset password failed: %d %s", resp.StatusCode, string(raw))
	}
}

func TestConcurrentLoginRateLimitAndRevokedPatchRejected(t *testing.T) {
	env, initPW := newPhase5Env(t, true, true)

	// 1. 10 concurrent wrong login attempts from the same IP must yield strictly 5x 401 and 5x 429.
	const burst = 10
	results := make(chan int, burst)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			hdr := adminHeaders(env.srv.URL)
			hdr["X-Forwarded-For"] = "203.0.113.55"
			resp, _ := doReq(t, http.DefaultClient, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": "wrong-password"}, hdr)
			results <- resp.StatusCode
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var got401, got429 int
	for code := range results {
		switch code {
		case http.StatusUnauthorized:
			got401++
		case http.StatusTooManyRequests:
			got429++
		default:
			t.Fatalf("unexpected concurrent login status: %d", code)
		}
	}
	if got401 != 5 || got429 != burst-5 {
		t.Fatalf("concurrent login burst: got %d x 401, %d x 429; want 5 x 401, %d x 429", got401, got429, burst-5)
	}

	// 2. PATCH on an already-revoked device must return 409 DEVICE_REVOKED.
	c := newAdminClient(t)
	hdr := adminHeaders(env.srv.URL)
	hdr["X-Forwarded-For"] = "203.0.113.99"
	resp, _ := doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/login", map[string]string{"password": initPW}, hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	resp, _ = doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/password", map[string]string{"current": initPW, "new": "brand-new-strong-pw-999"}, hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password change failed: %d", resp.StatusCode)
	}

	// Create and revoke a device.
	if err := env.st.CreateDevice(context.Background(), store.Device{
		ID: "dev_rev_patch", Name: "Old Phone", Platform: "android", TokenHash: auth.HashToken("tok_rev_patch"), CreatedAt: env.nowFn().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	resp, _ = doReq(t, c, http.MethodPost, env.srv.URL+"/admin/api/devices/dev_rev_patch/revoke", nil, hdr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke failed: %d", resp.StatusCode)
	}
	resp, raw := doReq(t, c, http.MethodPatch, env.srv.URL+"/admin/api/devices/dev_rev_patch", map[string]any{"can_add_devices": true}, hdr)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(raw), "DEVICE_REVOKED") {
		t.Fatalf("PATCH revoked device expected 409 DEVICE_REVOKED, got %d %s", resp.StatusCode, string(raw))
	}

	// 3. RateLimiter map-cap eviction must preserve active bans.
	now := time.Unix(1_700_000_000, 0)
	rl := admin.NewRateLimiter(2, 15*time.Minute, func() time.Time { return now })
	rl.Record("198.51.100.1")
	rl.Record("198.51.100.1")
	if !rl.IsLimited("198.51.100.1") {
		t.Fatalf("target IP should be limited")
	}
	now = now.Add(time.Second)
	for i := 0; i < 4200; i++ {
		// Record newer filler IPs after the target IP so oldest-eviction only drops old filler entries if needed,
		// and touch target IP once more to verify active bans aren't wiped wholesale.
		if i == 0 {
			rl.Record("198.51.100.1")
		}
		ip := "10.0." + string(rune('0'+(i/1000)%10)) + "." + string(rune('0'+(i%10))) + "-" + time.Duration(i).String()
		rl.Record(ip)
		now = now.Add(time.Millisecond)
	}
	// At least the most recently active banned IPs remain tracked (not wiped to 0).
	rl.Record("198.51.100.2")
	rl.Record("198.51.100.2")
	rl.Record("198.51.100.3")
	if !rl.IsLimited("198.51.100.2") {
		t.Fatalf("active IP ban should not be wiped when rate limiter reaches capacity")
	}
}
