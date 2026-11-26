package hub_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/store"
	"github.com/coder/websocket"
)

func openHubTestEnv(t *testing.T, cfg hub.Config) (*store.Store, *hub.Hub, *httptest.Server) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	h := hub.New(st, cfg)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		devID := r.URL.Query().Get("device_id")
		dev, err := st.GetDeviceByID(r.Context(), devID)
		if err != nil {
			http.Error(w, "unknown device", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		h.ServeConn(r.Context(), conn, dev, dev.LastSeq)
	}))
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		h.CloseAll(shutCtx)
		ts.Close()
	})
	return st, h, ts
}

func dialDevice(t *testing.T, ts *httptest.Server, devID string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "?device_id=" + devID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", devID, err)
	}
	return conn
}

func readJSONFrame(t *testing.T, conn *websocket.Conn, timeout time.Duration) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", string(data), err)
	}
	return m
}

func sendRelay(t *testing.T, conn *websocket.Conn, eventID string) {
	t.Helper()
	frame := map[string]any{
		"op":         "relay",
		"event_id":   eventID,
		"target":     "broadcast",
		"ciphertext": strings.Repeat("A", 64),
	}
	raw, _ := json.Marshal(frame)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatalf("write relay %s: %v", eventID, err)
	}
}

func TestReplayLiveRaceNoGapsNoDuplicatesStrictOrder(t *testing.T) {
	// Deliberately small SendBufferSize (8) vs MaxPendingReplay (128) to ensure
	// draining > SendBufferSize pending live events during replay never trips slow-consumer eviction.
	st, _, ts := openHubTestEnv(t, hub.Config{
		SendBufferSize:   8,
		MaxPendingReplay: 128,
	})
	ctx := context.Background()

	for _, d := range []store.Device{
		{ID: "dev_s1", Name: "S1", Platform: "android", TokenHash: "h_s1", CreatedAt: 1},
		{ID: "dev_s2", Name: "S2", Platform: "android", TokenHash: "h_s2", CreatedAt: 2},
		{ID: "dev_recv", Name: "Recv", Platform: "macos", TokenHash: "h_recv", CreatedAt: 3},
	} {
		if err := st.CreateDevice(ctx, d); err != nil {
			t.Fatalf("create %s: %v", d.ID, err)
		}
	}

	// Pre-populate 30 offline events for dev_recv before it connects.
	nowMs := time.Now().UnixMilli()
	expMs := nowMs + int64(time.Hour/time.Millisecond)
	const offlineCount = 30
	for i := 0; i < offlineCount; i++ {
		if _, err := st.EnqueueForOthers(ctx, "dev_s1", fmt.Sprintf("off_%03d", i), strings.Repeat("B", 64), nowMs, expMs); err != nil {
			t.Fatalf("enqueue offline %d: %v", i, err)
		}
	}

	connS1 := dialDevice(t, ts, "dev_s1")
	defer connS1.CloseNow()
	_ = readJSONFrame(t, connS1, 3*time.Second) // replay_complete

	connS2 := dialDevice(t, ts, "dev_s2")
	defer connS2.CloseNow()
	_ = readJSONFrame(t, connS2, 3*time.Second) // replay_complete

	// Concurrently blast 25 live events from EACH sender (50 live events > SendBufferSize=8)
	// while dev_recv connects and replays the 30 offline events.
	const livePerSender = 25
	var sendersWG sync.WaitGroup
	startCh := make(chan struct{})
	blast := func(conn *websocket.Conn, prefix string) {
		defer sendersWG.Done()
		<-startCh
		for i := 0; i < livePerSender; i++ {
			sendRelay(t, conn, fmt.Sprintf("%s_%03d", prefix, i))
		}
	}
	sendersWG.Add(2)
	go blast(connS1, "live1")
	go blast(connS2, "live2")

	// Start blasting right as receiver connects.
	close(startCh)
	connRecv := dialDevice(t, ts, "dev_recv")
	defer connRecv.CloseNow()

	totalExpected := offlineCount + 2*livePerSender
	seenIDs := make(map[string]struct{}, totalExpected)
	var lastSeq int64
	var replayCompleteSeq int64 = -1
	sawReplayComplete := false

	for len(seenIDs) < totalExpected || !sawReplayComplete {
		f := readJSONFrame(t, connRecv, 5*time.Second)
		switch f["op"] {
		case "replay_complete":
			if sawReplayComplete {
				t.Fatalf("received duplicate replay_complete: %v", f)
			}
			sawReplayComplete = true
			replayCompleteSeq = int64(f["latest_seq"].(float64))
			if replayCompleteSeq < lastSeq {
				t.Fatalf("replay_complete latest_seq=%d < lastSeq=%d", replayCompleteSeq, lastSeq)
			}
		case "event":
			seq := int64(f["seq"].(float64))
			id := f["event_id"].(string)
			if seq <= lastSeq {
				t.Fatalf("non-monotonic seq: got %d after %d (event_id=%s)", seq, lastSeq, id)
			}
			if sawReplayComplete && seq <= replayCompleteSeq {
				t.Fatalf("received event seq=%d <= replay_complete latest_seq=%d after replay_complete", seq, replayCompleteSeq)
			}
			if _, dup := seenIDs[id]; dup {
				t.Fatalf("duplicate event delivered: %s (seq=%d)", id, seq)
			}
			seenIDs[id] = struct{}{}
			lastSeq = seq
		default:
			t.Fatalf("unexpected frame: %v", f)
		}
	}

	sendersWG.Wait()
	if len(seenIDs) != totalExpected {
		t.Fatalf("received %d unique events, want %d", len(seenIDs), totalExpected)
	}
}

func TestSlowConsumerEvictionAndRecoveryReplay(t *testing.T) {
	st, _, ts := openHubTestEnv(t, hub.Config{
		SendBufferSize: 4,
	})
	ctx := context.Background()
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_s", Name: "Sender", Platform: "android", TokenHash: "hs", CreatedAt: 1})
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_slow", Name: "Slow", Platform: "macos", TokenHash: "hr", CreatedAt: 2})

	connS := dialDevice(t, ts, "dev_s")
	defer connS.CloseNow()
	_ = readJSONFrame(t, connS, 3*time.Second)

	connSlow := dialDevice(t, ts, "dev_slow")
	defer connSlow.CloseNow()
	connSlow.SetReadLimit(128 * 1024)
	_ = readJSONFrame(t, connSlow, 3*time.Second) // replay_complete

	// Stop reading from connSlow and blast enough bytes to saturate loopback TCP buffers + SendBufferSize (4).
	const burst = 80
	for i := 0; i < burst; i++ {
		frame := map[string]any{
			"op":         "relay",
			"event_id":   fmt.Sprintf("burst_%03d", i),
			"target":     "broadcast",
			"ciphertext": strings.Repeat("C", 50000),
		}
		raw, _ := json.Marshal(frame)
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := connS.Write(wctx, websocket.MessageText, raw)
		cancel()
		if err != nil {
			t.Fatalf("write burst %d: %v", i, err)
		}
	}

	// Eventually reading from connSlow must hit a close error (StatusPolicyViolation).
	var closeErr error
	for i := 0; i < burst+10; i++ {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, _, err := connSlow.Read(rctx)
		cancel()
		if err != nil {
			closeErr = err
			break
		}
	}
	if closeErr == nil {
		t.Fatalf("expected slow consumer to be disconnected, but read kept succeeding")
	}
	if status := websocket.CloseStatus(closeErr); status != websocket.StatusPolicyViolation {
		t.Fatalf("slow consumer close status = %v (err=%v), want StatusPolicyViolation", status, closeErr)
	}

	// Because nothing was acked, reconnecting must deliver all burst events cleanly
	// (those already persisted arrive before replay_complete; any still in flight from connS arrive live after).
	connRecovered := dialDevice(t, ts, "dev_slow")
	defer connRecovered.CloseNow()
	connRecovered.SetReadLimit(128 * 1024)
	seen := make(map[string]struct{}, burst)
	sawReplayComplete := false
	var lastSeq int64
	for len(seen) < burst || !sawReplayComplete {
		f := readJSONFrame(t, connRecovered, 5*time.Second)
		switch f["op"] {
		case "replay_complete":
			sawReplayComplete = true
		case "event":
			seq := int64(f["seq"].(float64))
			if seq <= lastSeq {
				t.Fatalf("non-monotonic seq on recovery: %d <= %d", seq, lastSeq)
			}
			lastSeq = seq
			id := f["event_id"].(string)
			if _, dup := seen[id]; dup {
				t.Fatalf("duplicate event on recovery: %s", id)
			}
			seen[id] = struct{}{}
		default:
			t.Fatalf("unexpected frame on recovery: %v", f)
		}
	}
	if len(seen) != burst {
		t.Fatalf("received %d unique events after slow-consumer reconnect, want %d", len(seen), burst)
	}
}

func TestKeepaliveTimeoutDropsSilentPeerPromptly(t *testing.T) {
	st, _, ts := openHubTestEnv(t, hub.Config{
		PingInterval: 40 * time.Millisecond,
		ReadTimeout:  120 * time.Millisecond,
	})
	ctx := context.Background()
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_silent", Name: "Silent", Platform: "macos", TokenHash: "h1", CreatedAt: 1})

	conn := dialDevice(t, ts, "dev_silent")
	defer conn.CloseNow()
	_ = readJSONFrame(t, conn, 3*time.Second) // replay_complete

	// Do NOT call conn.Read while keepalive timer runs so the client never sends Pong.
	start := time.Now()
	time.Sleep(250 * time.Millisecond)

	// Once we attempt to read again, the server must have already closed the socket promptly
	// (no 5-10s Close handshake hang).
	rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	_, _, err := conn.Read(rctx)
	cancel()
	if err == nil {
		t.Fatalf("expected silent peer connection to be dropped after keepalive timeout")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Fatalf("keepalive disconnect took %v, expected prompt drop (<1s)", elapsed)
	}
}

func TestCloseAllDeliversGoingAwayAndWaits(t *testing.T) {
	st, h, ts := openHubTestEnv(t, hub.Config{})
	ctx := context.Background()
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_1", Name: "One", Platform: "android", TokenHash: "h1", CreatedAt: 1})
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_2", Name: "Two", Platform: "macos", TokenHash: "h2", CreatedAt: 2})

	c1 := dialDevice(t, ts, "dev_1")
	defer c1.CloseNow()
	_ = readJSONFrame(t, c1, 3*time.Second)

	c2 := dialDevice(t, ts, "dev_2")
	defer c2.CloseNow()
	_ = readJSONFrame(t, c2, 3*time.Second)

	errCh := make(chan error, 2)
	for _, conn := range []*websocket.Conn{c1, c2} {
		go func(c *websocket.Conn) {
			rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _, err := c.Read(rctx)
			errCh <- err
		}(conn)
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h.CloseAll(shutCtx)

	for i := 0; i < 2; i++ {
		err := <-errCh
		if status := websocket.CloseStatus(err); status != websocket.StatusGoingAway {
			t.Fatalf("client %d close status = %v (err=%v), want StatusGoingAway", i, status, err)
		}
	}
}
