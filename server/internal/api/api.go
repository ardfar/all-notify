package api

import (
	"log/slog"
	"net/http"

	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/blobs"
	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/store"
)

type Server struct {
	store  *store.Store
	hub    *hub.Hub
	blobs  *blobs.Manager
	logger *slog.Logger
	mux    *http.ServeMux
}

func New(st *store.Store, h *hub.Hub, bm *blobs.Manager, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		store:  st,
		hub:    h,
		blobs:  bm,
		logger: logger,
		mux:    http.NewServeMux(),
	}

	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /v1/ws", auth.Middleware(st, http.HandlerFunc(s.handleWS)))
	s.mux.Handle("HEAD /v1/blobs/{blob_id}", auth.Middleware(st, http.HandlerFunc(s.handleBlobHead)))
	s.mux.Handle("PUT /v1/blobs/{blob_id}", auth.Middleware(st, http.HandlerFunc(s.handleBlobPut)))
	s.mux.Handle("GET /v1/blobs/{blob_id}", auth.Middleware(st, http.HandlerFunc(s.handleBlobGet)))

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
