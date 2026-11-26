package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/all-notify/server/internal/api"
	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/blobs"
	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/store"
	"github.com/coder/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type testEnv struct {
	st  *store.Store
	bm  *blobs.Manager
	h   *hub.Hub
	srv *httptest.Server
}

type deviceCreds struct {
	id    string
	token string
}

func newTestEnv(t *testing.T, hubCfg hub.Config, maxBlobBytes int64) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "all-notify.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bm, err := blobs.New(st, blobs.Config{
		Dir:           filepath.Join(dir, "blobs"),
		TTL:           24 * time.Hour,
		MaxBlobBytes:  maxBlobBytes,
		MaxTotalBytes: 4 * 1024 * 1024,
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("new blobs: %v", err)
	}
	if hubCfg.Logger == nil {
		hubCfg.Logger = logger
	}
	if hubCfg.RevocationCheckInterval == 0 {
		hubCfg.RevocationCheckInterval = 50 * time.Millisecond
	}
	h := hub.New(st, hubCfg)

	ctx, cancel := context.WithCancel(context.Background())
	go h.RunRevocationWatcher(ctx)
	t.Cleanup(func() {
		cancel()
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutCancel()
		h.CloseAll(shutCtx)
	})

	apiSrv := api.New(st, h, bm, logger)
	ts := httptest.NewServer(apiSrv)
	t.Cleanup(ts.Close)

	return &testEnv{st: st, bm: bm, h: h, srv: ts}
}

func (e *testEnv) addDevice(t *testing.T, id, name, platform string) deviceCreds {
	t.Helper()
	raw, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if err := e.st.CreateDevice(context.Background(), store.Device{
		ID:        id,
		Name:      name,
		Platform:  platform,
		TokenHash: hash,
		CreatedAt: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("create device %s: %v", id, err)
	}
	return deviceCreds{id: id, token: raw}
}

func (e *testEnv) dialWS(t *testing.T, token, query string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/v1/ws" + query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hdr := http.Header{}
	if token != "" {
		hdr.Set("Authorization", "Bearer "+token)
	}
	hdr.Set("X-AllNotify-Protocol", "1")
	return websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hdr})
}

func readFrame(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal frame %q: %v", string(data), err)
	}
	return m
}

func writeFrame(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatalf("ws write: %v", err)
	}
}

func makeEncryptedCiphertext(t *testing.T, kMaster []byte, eventID, senderID, plaintext string) string {
	t.Helper()
	r := hkdf.New(sha256.New, kMaster, nil, []byte("all-notify:v1:event"))
	kEvent := make([]byte, 32)
	_, _ = io.ReadFull(r, kEvent)
	aead, err := chacha20poly1305.NewX(kEvent)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x42}, chacha20poly1305.NonceSizeX)
	aad := "v1|" + eventID + "|" + senderID
	wire := append(append([]byte(nil), nonce...), aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))...)
	return base64.RawURLEncoding.EncodeToString(wire)
}

func decryptCiphertext(t *testing.T, kMaster []byte, eventID, senderID, ctB64 string) string {
	t.Helper()
	r := hkdf.New(sha256.New, kMaster, nil, []byte("all-notify:v1:event"))
	kEvent := make([]byte, 32)
	_, _ = io.ReadFull(r, kEvent)
	aead, err := chacha20poly1305.NewX(kEvent)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := base64.RawURLEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("decode b64: %v", err)
	}
	aad := "v1|" + eventID + "|" + senderID
	pt, err := aead.Open(nil, wire[:chacha20poly1305.NonceSizeX], wire[chacha20poly1305.NonceSizeX:], []byte(aad))
	if err != nil {
		t.Fatalf("decrypt event: %v", err)
	}
	return string(pt)
}

func TestHealthzAndAuthEnforcement(t *testing.T) {
	env := newTestEnv(t, hub.Config{}, 563200)
	dev := env.addDevice(t, "dev_1", "Pixel", "android")

	// /healthz requires no auth.
	resp, err := http.Get(env.srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
	}

	// Missing auth on WS -> 401.
	_, wsResp, err := env.dialWS(t, "", "")
	if err == nil || wsResp == nil || wsResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got err=%v resp=%v", err, wsResp)
	}

	// Wrong protocol header -> 400.
	wsURL := "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/v1/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, wsResp, err = websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":        []string{"Bearer " + dev.token},
			"X-AllNotify-Protocol": []string{"2"},
		},
	})
	if err == nil || wsResp == nil || wsResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong protocol version, got err=%v resp=%v", err, wsResp)
	}

	// Invalid after_seq -> 400.
	_, wsResp, err = env.dialWS(t, dev.token, "?after_seq=-5")
	if err == nil || wsResp == nil || wsResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative after_seq, got err=%v resp=%v", err, wsResp)
	}
}

func TestWSFanOutNoEchoOfflineReplayAndAck(t *testing.T) {
	env := newTestEnv(t, hub.Config{}, 563200)
	phoneA := env.addDevice(t, "dev_phone_a", "Pixel 9", "android")
	phoneB := env.addDevice(t, "dev_phone_b", "Galaxy", "android")
	mac := env.addDevice(t, "dev_mac", "MacBook Pro", "macos")

	kMaster, _, _ := auth.GenerateMasterKey()

	// Connect Phone A and Phone B (Mac stays offline for now).
	connA, _, err := env.dialWS(t, phoneA.token, "")
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.CloseNow()
	if f := readFrame(t, connA); f["op"] != "replay_complete" || f["latest_seq"].(float64) != 0 {
		t.Fatalf("unexpected initial frame A: %v", f)
	}

	connB, _, err := env.dialWS(t, phoneB.token, "")
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.CloseNow()
	if f := readFrame(t, connB); f["op"] != "replay_complete" {
		t.Fatalf("unexpected initial frame B: %v", f)
	}

	// Phone A relays two E2EE events.
	pt1 := `{"type":"notification.posted","title":"Hello 1"}`
	ct1 := makeEncryptedCiphertext(t, kMaster, "evt_0001", phoneA.id, pt1)
	writeFrame(t, connA, map[string]any{
		"op": "relay", "event_id": "evt_0001", "target": "broadcast", "ciphertext": ct1,
	})

	pt2 := `{"type":"notification.dismissed","notification_uids":["u1"]}`
	ct2 := makeEncryptedCiphertext(t, kMaster, "evt_0002", phoneA.id, pt2)
	writeFrame(t, connA, map[string]any{
		"op": "relay", "event_id": "evt_0002", "target": "broadcast", "ciphertext": ct2,
	})

	// Phone B receives both live events and decrypts them with K_event + AAD.
	gotB1 := readFrame(t, connB)
	if gotB1["op"] != "event" || gotB1["event_id"] != "evt_0001" || gotB1["sender_device_id"] != phoneA.id {
		t.Fatalf("unexpected B1: %v", gotB1)
	}
	if dec := decryptCiphertext(t, kMaster, "evt_0001", phoneA.id, gotB1["ciphertext"].(string)); dec != pt1 {
		t.Fatalf("decrypted B1 = %q, want %q", dec, pt1)
	}

	gotB2 := readFrame(t, connB)
	if gotB2["op"] != "event" || gotB2["event_id"] != "evt_0002" {
		t.Fatalf("unexpected B2: %v", gotB2)
	}

	// Verify Phone A received NO echo.
	noEchoCtx, noEchoCancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	_, _, echoErr := connA.Read(noEchoCtx)
	noEchoCancel()
	if !errors.Is(echoErr, context.DeadlineExceeded) {
		t.Fatalf("expected no echo to sender A, got err=%v", echoErr)
	}

	// Mac wakes up and receives both buffered offline events BEFORE replay_complete.
	connMac, _, err := env.dialWS(t, mac.token, "")
	if err != nil {
		t.Fatalf("dial Mac: %v", err)
	}
	m1 := readFrame(t, connMac)
	m2 := readFrame(t, connMac)
	mDone := readFrame(t, connMac)
	if m1["event_id"] != "evt_0001" || m2["event_id"] != "evt_0002" {
		t.Fatalf("unexpected Mac replay order: m1=%v m2=%v", m1, m2)
	}
	seq1 := int64(m1["seq"].(float64))
	seq2 := int64(m2["seq"].(float64))
	if mDone["op"] != "replay_complete" || int64(mDone["latest_seq"].(float64)) != seq2 {
		t.Fatalf("unexpected Mac replay_complete: %v (want latest_seq=%d)", mDone, seq2)
	}

	// Ack only seq1, disconnect, reconnect -> only evt_0002 should replay.
	writeFrame(t, connMac, map[string]any{"op": "ack", "seq": seq1})
	// Wait briefly for server to persist ack before closing.
	time.Sleep(50 * time.Millisecond)
	_ = connMac.Close(websocket.StatusNormalClosure, "bye")

	connMac2, _, err := env.dialWS(t, mac.token, "")
	if err != nil {
		t.Fatalf("dial Mac #2: %v", err)
	}
	m2Again := readFrame(t, connMac2)
	mDone2 := readFrame(t, connMac2)
	if m2Again["event_id"] != "evt_0002" || mDone2["op"] != "replay_complete" {
		t.Fatalf("expected only evt_0002 after partial ack, got %v then %v", m2Again, mDone2)
	}

	// Ack seq2, disconnect, reconnect -> 0 events, replay_complete with latest_seq == seq2.
	writeFrame(t, connMac2, map[string]any{"op": "ack", "seq": seq2})
	time.Sleep(50 * time.Millisecond)
	_ = connMac2.Close(websocket.StatusNormalClosure, "bye")

	connMac3, _, err := env.dialWS(t, mac.token, "")
	if err != nil {
		t.Fatalf("dial Mac #3: %v", err)
	}
	defer connMac3.CloseNow()
	mDone3 := readFrame(t, connMac3)
	if mDone3["op"] != "replay_complete" || int64(mDone3["latest_seq"].(float64)) != seq2 {
		t.Fatalf("expected empty replay_complete at seq=%d, got %v", seq2, mDone3)
	}
}

func TestWSDuplicateReplacementAndRevocation(t *testing.T) {
	env := newTestEnv(t, hub.Config{RevocationCheckInterval: 40 * time.Millisecond}, 563200)
	devA := env.addDevice(t, "dev_a", "Phone A", "android")
	devB := env.addDevice(t, "dev_b", "Phone B", "android")

	conn1, _, err := env.dialWS(t, devA.token, "")
	if err != nil {
		t.Fatalf("dial conn1: %v", err)
	}
	_ = readFrame(t, conn1) // replay_complete

	// Second connection for same device replaces conn1 cleanly (1000).
	conn2, _, err := env.dialWS(t, devA.token, "")
	if err != nil {
		t.Fatalf("dial conn2: %v", err)
	}
	defer conn2.CloseNow()
	_ = readFrame(t, conn2) // replay_complete

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _, closeErr := conn1.Read(ctx)
	cancel()
	if websocket.CloseStatus(closeErr) != websocket.StatusNormalClosure {
		t.Fatalf("old conn close status = %v (err=%v), want StatusNormalClosure", websocket.CloseStatus(closeErr), closeErr)
	}

	// Verify conn2 is still registered and receives events from devB.
	connB, _, err := env.dialWS(t, devB.token, "")
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.CloseNow()
	_ = readFrame(t, connB)

	kMaster, _, _ := auth.GenerateMasterKey()
	ct := makeEncryptedCiphertext(t, kMaster, "evt_dup_test", devB.id, `{"type":"notification.posted"}`)
	writeFrame(t, connB, map[string]any{"op": "relay", "event_id": "evt_dup_test", "target": "broadcast", "ciphertext": ct})

	if got := readFrame(t, conn2); got["event_id"] != "evt_dup_test" {
		t.Fatalf("replacement conn2 did not receive event: %v", got)
	}

	// Revoke devA in SQLite (simulating CLI `token revoke`) -> watcher must close conn2 with PolicyViolation.
	ok, err := env.st.RevokeDevice(context.Background(), devA.id, time.Now().UnixMilli())
	if err != nil || !ok {
		t.Fatalf("RevokeDevice: ok=%v err=%v", ok, err)
	}

	rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _, revErr := conn2.Read(rctx)
	rcancel()
	if websocket.CloseStatus(revErr) != websocket.StatusPolicyViolation {
		t.Fatalf("revoked conn close status = %v (err=%v), want StatusPolicyViolation", websocket.CloseStatus(revErr), revErr)
	}

	// Reconnecting with revoked token must return 401.
	_, resp, err := env.dialWS(t, devA.token, "")
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token reconnect should fail with 401, got err=%v resp=%v", err, resp)
	}
}

func TestWSRevokedSenderRelayRejectedImmediately(t *testing.T) {
	// Long watcher interval ensures rejection comes from the relay handler itself.
	env := newTestEnv(t, hub.Config{RevocationCheckInterval: time.Hour}, 563200)
	sender := env.addDevice(t, "dev_sender", "Phone", "android")
	recv := env.addDevice(t, "dev_recv", "Mac", "macos")

	connS, _, err := env.dialWS(t, sender.token, "")
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer connS.CloseNow()
	_ = readFrame(t, connS)

	connR, _, err := env.dialWS(t, recv.token, "")
	if err != nil {
		t.Fatalf("dial recv: %v", err)
	}
	defer connR.CloseNow()
	_ = readFrame(t, connR)

	// Revoke sender while connected.
	if _, err := env.st.RevokeDevice(context.Background(), sender.id, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}

	kMaster, _, _ := auth.GenerateMasterKey()
	ct := makeEncryptedCiphertext(t, kMaster, "evt_revoked_send", sender.id, `{"type":"notification.posted"}`)
	writeFrame(t, connS, map[string]any{"op": "relay", "event_id": "evt_revoked_send", "target": "broadcast", "ciphertext": ct})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _, readErr := connS.Read(ctx)
	cancel()
	if websocket.CloseStatus(readErr) != websocket.StatusPolicyViolation {
		t.Fatalf("expected StatusPolicyViolation on revoked sender relay, got %v (err=%v)", websocket.CloseStatus(readErr), readErr)
	}

	// Recipient must not have received anything.
	rctx, rcancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	_, _, recvErr := connR.Read(rctx)
	rcancel()
	if !errors.Is(recvErr, context.DeadlineExceeded) {
		t.Fatalf("recipient should not receive event from revoked sender, got err=%v", recvErr)
	}
}

func TestWSKeepalivePingPong(t *testing.T) {
	env := newTestEnv(t, hub.Config{
		PingInterval: 50 * time.Millisecond,
		ReadTimeout:  200 * time.Millisecond,
	}, 563200)
	dev := env.addDevice(t, "dev_ping", "Mac", "macos")

	conn, _, err := env.dialWS(t, dev.token, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	_ = readFrame(t, conn)

	// Actively reading causes coder/websocket client to auto-respond to server Pings.
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	_, _, err = conn.Read(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("healthy client should stay connected across pings, got err=%v", err)
	}
}

func TestWSValidationAndOversizeErrorFrames(t *testing.T) {
	env := newTestEnv(t, hub.Config{MaxEventBytes: 1024}, 563200)
	dev := env.addDevice(t, "dev_v", "Phone", "android")

	conn, _, err := env.dialWS(t, dev.token, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	_ = readFrame(t, conn) // replay_complete

	// Oversize frame (>1024 bytes, <=2048 bytes) -> PAYLOAD_TOO_LARGE.
	writeFrame(t, conn, map[string]any{
		"op":         "relay",
		"event_id":   "evt_big",
		"target":     "broadcast",
		"ciphertext": strings.Repeat("A", 1100),
	})
	errFrame := readFrame(t, conn)
	if errFrame["op"] != "error" || errFrame["code"] != "PAYLOAD_TOO_LARGE" {
		t.Fatalf("expected PAYLOAD_TOO_LARGE error frame, got %v", errFrame)
	}

	// AAD injection attempt (`|` in event_id) -> INVALID_FRAME.
	writeFrame(t, conn, map[string]any{
		"op":         "relay",
		"event_id":   "evt|inject",
		"target":     "broadcast",
		"ciphertext": strings.Repeat("A", 64),
	})
	errFrame = readFrame(t, conn)
	if errFrame["op"] != "error" || errFrame["code"] != "INVALID_FRAME" {
		t.Fatalf("expected INVALID_FRAME for pipe event_id, got %v", errFrame)
	}

	// Extra unknown field -> INVALID_FRAME.
	writeFrame(t, conn, map[string]any{
		"op":         "relay",
		"event_id":   "evt_extra",
		"target":     "broadcast",
		"ciphertext": strings.Repeat("A", 64),
		"extra":      true,
	})
	errFrame = readFrame(t, conn)
	if errFrame["op"] != "error" || errFrame["code"] != "INVALID_FRAME" {
		t.Fatalf("expected INVALID_FRAME for unknown field, got %v", errFrame)
	}
}

func TestBlobHTTPAPI(t *testing.T) {
	env := newTestEnv(t, hub.Config{}, 512)
	dev := env.addDevice(t, "dev_blob", "Pixel 9", "android")
	client := env.srv.Client()

	doReq := func(method, path, token string, body []byte) *http.Response {
		t.Helper()
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, env.srv.URL+path, r)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	blobID := "icon_e3b0c44298fc1c14"
	// Unauthenticated -> 401.
	resp := doReq(http.MethodHead, "/v1/blobs/"+blobID, "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth HEAD = %d, want 401", resp.StatusCode)
	}

	// HEAD before PUT -> 404.
	resp = doReq(http.MethodHead, "/v1/blobs/"+blobID, dev.token, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing HEAD = %d, want 404", resp.StatusCode)
	}

	// Invalid blob_id -> 400.
	resp = doReq(http.MethodPut, "/v1/blobs/short", dev.token, []byte("abc"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid id PUT = %d, want 400", resp.StatusCode)
	}

	// Oversize PUT (>512 bytes) -> 413.
	resp = doReq(http.MethodPut, "/v1/blobs/"+blobID, dev.token, bytes.Repeat([]byte{0x01}, 513))
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize PUT = %d, want 413", resp.StatusCode)
	}

	// Valid PUT using real ciphertext hex from protocol/test_vectors.json.
	payload, _ := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b79a094b90c459ab12339b582eb1744ae18ff483155a7ece54303b0fdae9bd09136af166b9ac4328a1e68ba35d09a537d0")
	resp = doReq(http.MethodPut, "/v1/blobs/"+blobID, dev.token, payload)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT = %d, want 201", resp.StatusCode)
	}

	// HEAD -> 200 with Content-Length.
	resp = doReq(http.MethodHead, "/v1/blobs/"+blobID, dev.token, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength != int64(len(payload)) {
		t.Fatalf("HEAD = %d len=%d, want 200 len=%d", resp.StatusCode, resp.ContentLength, len(payload))
	}

	// GET -> 200 with exact bytes & application/octet-stream.
	resp = doReq(http.MethodGet, "/v1/blobs/"+blobID, dev.token, nil)
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/octet-stream" || !bytes.Equal(got, payload) {
		t.Fatalf("GET status=%d ct=%q len=%d", resp.StatusCode, resp.Header.Get("Content-Type"), len(got))
	}
}
