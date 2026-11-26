package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/all-notify/server/internal/store"
	"github.com/coder/websocket"
)

const (
	defaultSendBuffer       = 128
	defaultMaxPendingReplay = 256
	defaultWriteTimeout     = 15 * time.Second
)

var (
	idPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	ciphertextPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

type Config struct {
	TTL                     time.Duration
	MaxEventBytes           int
	PingInterval            time.Duration
	ReadTimeout             time.Duration
	RevocationCheckInterval time.Duration
	SendBufferSize          int
	MaxPendingReplay        int
	Now                     func() time.Time
	Logger                  *slog.Logger
	BeforeWrite             func(ctx context.Context, deviceID string)
}

type EventFrame struct {
	Op             string `json:"op"`
	Seq            int64  `json:"seq"`
	EventID        string `json:"event_id"`
	SenderDeviceID string `json:"sender_device_id"`
	ServerTS       int64  `json:"server_ts"`
	Ciphertext     string `json:"ciphertext"`
}

type ReplayCompleteFrame struct {
	Op        string `json:"op"`
	LatestSeq int64  `json:"latest_seq"`
}

type ErrorFrame struct {
	Op      string `json:"op"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type opEnvelope struct {
	Op string `json:"op"`
}

type relayFrame struct {
	Op         string `json:"op"`
	EventID    string `json:"event_id"`
	Target     string `json:"target"`
	Ciphertext string `json:"ciphertext"`
}

type ackFrame struct {
	Op  string `json:"op"`
	Seq *int64 `json:"seq"`
}

type client struct {
	deviceID    string
	conn        *websocket.Conn
	cancel      context.CancelFunc
	send        chan []byte
	closeOnce   sync.Once
	closeDone   chan struct{}
	mu          sync.Mutex
	replaying   bool
	lastSentSeq int64
	pending     []EventFrame
}

func (c *client) closeWithStatus(status websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		// Write the close frame before cancelling connCtx; canceling Read's ctx first
		// causes coder/websocket to drop the TCP socket with EOF instead of a close frame.
		go func() {
			defer close(c.closeDone)
			_ = c.conn.Close(status, reason)
			c.cancel()
		}()
	})
}

func (c *client) closeNow() {
	c.closeOnce.Do(func() {
		defer close(c.closeDone)
		c.cancel()
		_ = c.conn.CloseNow()
	})
}

type Hub struct {
	store                   *store.Store
	ttl                     time.Duration
	maxEventBytes           int
	pingInterval            time.Duration
	readTimeout             time.Duration
	revocationCheckInterval time.Duration
	sendBufferSize          int
	maxPendingReplay        int
	now                     func() time.Time
	logger                  *slog.Logger
	beforeWrite             func(ctx context.Context, deviceID string)

	relayMu sync.Mutex
	wg      sync.WaitGroup

	mu      sync.RWMutex
	clients map[string]*client
}

func New(st *store.Store, cfg Config) *Hub {
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.MaxEventBytes <= 0 {
		cfg.MaxEventBytes = 65536
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 90 * time.Second
	}
	if cfg.RevocationCheckInterval <= 0 {
		cfg.RevocationCheckInterval = time.Second
	}
	if cfg.SendBufferSize <= 0 {
		cfg.SendBufferSize = defaultSendBuffer
	}
	if cfg.MaxPendingReplay <= 0 {
		cfg.MaxPendingReplay = defaultMaxPendingReplay
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Hub{
		store:                   st,
		ttl:                     cfg.TTL,
		maxEventBytes:           cfg.MaxEventBytes,
		pingInterval:            cfg.PingInterval,
		readTimeout:             cfg.ReadTimeout,
		revocationCheckInterval: cfg.RevocationCheckInterval,
		sendBufferSize:          cfg.SendBufferSize,
		maxPendingReplay:        cfg.MaxPendingReplay,
		now:                     cfg.Now,
		logger:                  cfg.Logger,
		beforeWrite:             cfg.BeforeWrite,
		clients:                 make(map[string]*client),
	}
}

func (h *Hub) register(c *client) {
	h.mu.Lock()
	old := h.clients[c.deviceID]
	h.clients[c.deviceID] = c
	h.mu.Unlock()

	if old != nil {
		h.logger.Info("replacing active websocket for device", "device_id", c.deviceID)
		old.closeWithStatus(websocket.StatusNormalClosure, "replaced by new connection")
	}
}

func (h *Hub) unregister(c *client) {
	h.mu.Lock()
	if cur, ok := h.clients[c.deviceID]; ok && cur == c {
		delete(h.clients, c.deviceID)
	}
	h.mu.Unlock()
}

func (h *Hub) IsOnline(deviceID string) bool {
	h.mu.RLock()
	_, ok := h.clients[deviceID]
	h.mu.RUnlock()
	return ok
}

func (h *Hub) DisconnectDevice(deviceID, reason string) bool {
	h.mu.Lock()
	c, ok := h.clients[deviceID]
	if ok {
		delete(h.clients, deviceID)
	}
	h.mu.Unlock()

	if !ok {
		return false
	}
	c.closeWithStatus(websocket.StatusPolicyViolation, reason)
	return true
}

func (h *Hub) CloseAll(ctx context.Context) {
	h.mu.Lock()
	all := make([]*client, 0, len(h.clients))
	for id, c := range h.clients {
		all = append(all, c)
		delete(h.clients, id)
	}
	h.mu.Unlock()

	for _, c := range all {
		c.closeWithStatus(websocket.StatusGoingAway, "server shutting down")
	}

	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		for _, c := range all {
			c.cancel()
			_ = c.conn.CloseNow()
		}
		<-done
	}
}

// RunRevocationWatcher disconnects devices revoked via CLI while the server is running.
func (h *Hub) RunRevocationWatcher(ctx context.Context) {
	ticker := time.NewTicker(h.revocationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.RLock()
			ids := make([]string, 0, len(h.clients))
			for id := range h.clients {
				ids = append(ids, id)
			}
			h.mu.RUnlock()
			if len(ids) == 0 {
				continue
			}
			revoked, err := h.store.ListRevokedOrMissing(ctx, ids)
			if err != nil {
				if ctx.Err() == nil {
					h.logger.Warn("revocation check failed", "error", err)
				}
				continue
			}
			for _, id := range revoked {
				h.logger.Info("disconnecting revoked device", "device_id", id)
				h.DisconnectDevice(id, "device revoked")
			}
		}
	}
}

func (h *Hub) deliver(recipientID string, frame EventFrame) {
	h.mu.RLock()
	c, ok := h.clients[recipientID]
	h.mu.RUnlock()
	if !ok {
		return
	}

	raw, err := json.Marshal(frame)
	if err != nil {
		return
	}

	c.mu.Lock()
	if c.replaying {
		if len(c.pending) >= h.maxPendingReplay {
			c.mu.Unlock()
			h.closeSlowConsumer(c)
			return
		}
		c.pending = append(c.pending, frame)
		c.mu.Unlock()
		return
	}
	if frame.Seq <= c.lastSentSeq {
		c.mu.Unlock()
		return
	}
	c.lastSentSeq = frame.Seq
	select {
	case c.send <- raw:
		c.mu.Unlock()
	default:
		c.mu.Unlock()
		h.closeSlowConsumer(c)
	}
}

func (h *Hub) enqueueSend(c *client, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case c.send <- raw:
	default:
		h.closeSlowConsumer(c)
	}
}

func (h *Hub) closeSlowConsumer(c *client) {
	h.unregister(c)
	h.logger.Warn("closing slow websocket consumer", "device_id", c.deviceID)
	c.closeWithStatus(websocket.StatusPolicyViolation, "slow consumer")
}

func writeJSON(ctx context.Context, conn *websocket.Conn, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, defaultWriteTimeout)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, raw)
}

func (h *Hub) ServeConn(ctx context.Context, conn *websocket.Conn, dev *store.Device, afterSeq int64) {
	h.wg.Add(1)
	defer h.wg.Done()

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Allow frames slightly above maxEventBytes to reach our check so we can reply with PAYLOAD_TOO_LARGE.
	conn.SetReadLimit(int64(h.maxEventBytes * 2))

	c := &client{
		deviceID:  dev.ID,
		conn:      conn,
		cancel:    cancel,
		send:      make(chan []byte, h.sendBufferSize),
		closeDone: make(chan struct{}),
		replaying: true,
	}
	defer func() {
		c.closeNow()
		<-c.closeDone
	}()
	h.register(c)
	defer h.unregister(c)

	_ = h.store.UpdateDeviceLastSeen(connCtx, dev.ID, h.now().UnixMilli())

	// 1. Offline replay before live writer starts so replay_complete is a strict wire boundary.
	queued, err := h.store.QueryOfflineEvents(connCtx, dev.ID, afterSeq, h.now().UnixMilli())
	if err != nil {
		h.logger.Warn("replay query failed", "device_id", dev.ID, "error", err)
		c.closeWithStatus(websocket.StatusInternalError, "replay failed")
		return
	}

	latestSeq := afterSeq
	for _, ev := range queued {
		if ev.Seq > latestSeq {
			latestSeq = ev.Seq
		}
		frame := EventFrame{
			Op:             "event",
			Seq:            ev.Seq,
			EventID:        ev.EventID,
			SenderDeviceID: ev.SenderDeviceID,
			ServerTS:       ev.CreatedAt,
			Ciphertext:     ev.Ciphertext,
		}
		if err := writeJSON(connCtx, conn, frame); err != nil {
			return
		}
	}
	if err := writeJSON(connCtx, conn, ReplayCompleteFrame{
		Op:        "replay_complete",
		LatestSeq: latestSeq,
	}); err != nil {
		return
	}

	// Drain any live events buffered during replay in strict seq order before flipping to live mode.
	for {
		c.mu.Lock()
		if len(c.pending) == 0 {
			c.lastSentSeq = latestSeq
			c.replaying = false
			c.mu.Unlock()
			break
		}
		batch := c.pending
		c.pending = nil
		c.mu.Unlock()

		for _, ev := range batch {
			if ev.Seq <= latestSeq {
				continue
			}
			latestSeq = ev.Seq
			if err := writeJSON(connCtx, conn, ev); err != nil {
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 2. Writer goroutine.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-connCtx.Done():
				return
			case payload := <-c.send:
				if h.beforeWrite != nil {
					h.beforeWrite(connCtx, dev.ID)
				}
				if connCtx.Err() != nil {
					return
				}
				wctx, wcancel := context.WithTimeout(connCtx, defaultWriteTimeout)
				err := conn.Write(wctx, websocket.MessageText, payload)
				wcancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// 3. Keepalive goroutine (Ping every 30s; drop if no pong within readTimeout - pingInterval).
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(h.pingInterval)
		defer ticker.Stop()

		pongWait := h.readTimeout - h.pingInterval
		if pongWait <= 0 {
			pongWait = h.readTimeout
		}
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				pctx, pcancel := context.WithTimeout(connCtx, pongWait)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					if connCtx.Err() == nil {
						h.logger.Info("websocket keepalive timeout", "device_id", dev.ID)
						h.unregister(c)
						c.closeNow()
					}
					return
				}
			}
		}
	}()

	// 4. Reader loop.
	for {
		msgType, data, err := conn.Read(connCtx)
		if err != nil {
			break
		}
		if msgType != websocket.MessageText {
			h.sendError(c, "INVALID_FRAME", "expected text JSON frame")
			continue
		}
		if len(data) > h.maxEventBytes {
			h.sendError(c, "PAYLOAD_TOO_LARGE", "event exceeds 64KB limit")
			continue
		}
		if !h.handleFrame(connCtx, c, data) {
			break
		}
	}

	cancel()
	wg.Wait()
}

func (h *Hub) sendError(c *client, code, message string) {
	h.enqueueSend(c, ErrorFrame{
		Op:      "error",
		Code:    code,
		Message: message,
	})
}

func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// handleFrame returns false if the connection should be terminated.
func (h *Hub) handleFrame(ctx context.Context, c *client, data []byte) bool {
	var env opEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		h.sendError(c, "INVALID_FRAME", "malformed JSON frame")
		return true
	}

	switch env.Op {
	case "relay":
		var f relayFrame
		if err := decodeStrict(data, &f); err != nil {
			h.sendError(c, "INVALID_FRAME", "invalid relay frame")
			return true
		}
		if f.Target != "broadcast" {
			h.sendError(c, "INVALID_FRAME", "target must be broadcast")
			return true
		}
		if !idPattern.MatchString(f.EventID) {
			h.sendError(c, "INVALID_FRAME", "invalid event_id")
			return true
		}
		if len(f.Ciphertext) > h.maxEventBytes {
			h.sendError(c, "PAYLOAD_TOO_LARGE", "event exceeds 64KB limit")
			return true
		}
		if len(f.Ciphertext) < 54 || !ciphertextPattern.MatchString(f.Ciphertext) {
			h.sendError(c, "INVALID_FRAME", "ciphertext must be valid unpadded base64url")
			return true
		}

		nowMs := h.now().UnixMilli()
		expiresAtMs := nowMs + h.ttl.Milliseconds()

		// Serialize DB enqueue + live delivery so every recipient sees events in strict seq order.
		h.relayMu.Lock()
		events, err := h.store.EnqueueForOthers(ctx, c.deviceID, f.EventID, f.Ciphertext, nowMs, expiresAtMs)
		if err != nil {
			h.relayMu.Unlock()
			if errors.Is(err, store.ErrDeviceRevoked) {
				h.unregister(c)
				c.closeWithStatus(websocket.StatusPolicyViolation, "device revoked")
				return false
			}
			h.logger.Error("enqueue relay event failed", "device_id", c.deviceID, "event_id", f.EventID, "error", err)
			h.sendError(c, "INTERNAL_ERROR", "failed to persist event")
			return true
		}

		for _, ev := range events {
			h.deliver(ev.RecipientID, EventFrame{
				Op:             "event",
				Seq:            ev.Seq,
				EventID:        ev.EventID,
				SenderDeviceID: ev.SenderDeviceID,
				ServerTS:       ev.CreatedAt,
				Ciphertext:     ev.Ciphertext,
			})
		}
		h.relayMu.Unlock()
		return true

	case "ack":
		var f ackFrame
		if err := decodeStrict(data, &f); err != nil || f.Seq == nil || *f.Seq < 0 {
			h.sendError(c, "INVALID_FRAME", "invalid ack frame")
			return true
		}
		if err := h.store.AckEvents(ctx, c.deviceID, *f.Seq, h.now().UnixMilli()); err != nil {
			if errors.Is(err, store.ErrDeviceRevoked) {
				h.unregister(c)
				c.closeWithStatus(websocket.StatusPolicyViolation, "device revoked")
				return false
			}
			h.logger.Warn("ack events failed", "device_id", c.deviceID, "seq", *f.Seq, "error", err)
			h.sendError(c, "INTERNAL_ERROR", "failed to persist ack")
		}
		return true

	default:
		h.sendError(c, "INVALID_FRAME", "unsupported op")
		return true
	}
}
