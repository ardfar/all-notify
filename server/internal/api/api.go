package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/all-notify/server/internal/admin"
	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/blobs"
	"github.com/all-notify/server/internal/hub"
	"github.com/all-notify/server/internal/pairing"
	"github.com/all-notify/server/internal/store"
)

type Options struct {
	Logger          *slog.Logger
	AdminEnabled    bool
	PairingCodeTTL  time.Duration
	AdminSessionTTL time.Duration
	TrustProxy      bool
	Now             func() time.Time
}

type Server struct {
	store      *store.Store
	hub        *hub.Hub
	blobs      *blobs.Manager
	pairing    *pairing.Service
	claimLimit *admin.RateLimiter
	trustProxy bool
	logger     *slog.Logger
	mux        *http.ServeMux
}

func New(st *store.Store, h *hub.Hub, bm *blobs.Manager, logger *slog.Logger) *Server {
	return NewWithOptions(st, h, bm, Options{
		Logger:       logger,
		AdminEnabled: true,
	})
}

func NewWithOptions(st *store.Store, h *hub.Hub, bm *blobs.Manager, opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	ps := pairing.New(st, pairing.Config{
		TTL: opts.PairingCodeTTL,
		Now: nowFn,
	})

	s := &Server{
		store:      st,
		hub:        h,
		blobs:      bm,
		pairing:    ps,
		claimLimit: admin.NewRateLimiter(10, time.Minute, nowFn),
		trustProxy: opts.TrustProxy,
		logger:     logger,
		mux:        http.NewServeMux(),
	}

	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /v1/ws", auth.Middleware(st, http.HandlerFunc(s.handleWS)))
	s.mux.Handle("HEAD /v1/blobs/{blob_id}", auth.Middleware(st, http.HandlerFunc(s.handleBlobHead)))
	s.mux.Handle("PUT /v1/blobs/{blob_id}", auth.Middleware(st, http.HandlerFunc(s.handleBlobPut)))
	s.mux.Handle("GET /v1/blobs/{blob_id}", auth.Middleware(st, http.HandlerFunc(s.handleBlobGet)))

	s.mux.HandleFunc("POST /v1/pair/claim", s.handlePairClaim)
	s.mux.Handle("GET /v1/me", auth.Middleware(st, http.HandlerFunc(s.handleMe)))
	s.mux.Handle("POST /v1/pairing-codes", auth.Middleware(st, http.HandlerFunc(s.handleDeviceCreatePairingCode)))
	s.mux.Handle("GET /v1/pairing-codes", auth.Middleware(st, http.HandlerFunc(s.handleDeviceListPairingCodes)))

	if opts.AdminEnabled {
		adminHandler := admin.NewHandler(st, h, ps, admin.Config{
			SessionTTL: opts.AdminSessionTTL,
			TrustProxy: opts.TrustProxy,
			Now:        nowFn,
			Logger:     logger,
		})
		adminHandler.RegisterRoutes(s.mux)
	}

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
