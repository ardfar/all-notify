package api

import (
	"net/http"
	"strconv"

	"github.com/all-notify/server/internal/auth"
	"github.com/coder/websocket"
)

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	dev, ok := auth.DeviceFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Header.Get("X-AllNotify-Protocol") != "1" {
		http.Error(w, "missing or unsupported X-AllNotify-Protocol header (expected 1)", http.StatusBadRequest)
		return
	}

	afterSeq := dev.LastSeq
	if rawAfter := r.URL.Query().Get("after_seq"); rawAfter != "" {
		v, err := strconv.ParseInt(rawAfter, 10, 64)
		if err != nil || v < 0 {
			http.Error(w, "invalid after_seq query parameter", http.StatusBadRequest)
			return
		}
		afterSeq = v
	}

	// Non-browser native clients authenticate with Bearer tokens rather than cookies.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.logger.Warn("websocket accept failed", "device_id", dev.ID, "error", err)
		return
	}

	s.hub.ServeConn(r.Context(), conn, dev, afterSeq)
}
