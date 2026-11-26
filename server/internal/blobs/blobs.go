package blobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/all-notify/server/internal/store"
)

var (
	ErrInvalidBlobID = errors.New("invalid blob_id")
	ErrBlobTooLarge  = errors.New("blob exceeds max size")
	ErrEmptyBlob     = errors.New("blob body is empty")

	blobIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)
)

type Config struct {
	Dir           string
	TTL           time.Duration
	MaxBlobBytes  int64
	MaxTotalBytes int64
	Now           func() time.Time
	Logger        *slog.Logger
}

type Manager struct {
	db            *store.Store
	dir           string
	ttl           time.Duration
	maxBlobBytes  int64
	maxTotalBytes int64
	now           func() time.Time
	logger        *slog.Logger
	mu            sync.RWMutex
}

func New(db *store.Store, cfg Config) (*Manager, error) {
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("create blobs dir: %w", err)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.MaxBlobBytes <= 0 {
		cfg.MaxBlobBytes = 563200
	}
	if cfg.MaxTotalBytes <= 0 {
		cfg.MaxTotalBytes = 256 * 1024 * 1024
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Manager{
		db:            db,
		dir:           cfg.Dir,
		ttl:           cfg.TTL,
		maxBlobBytes:  cfg.MaxBlobBytes,
		maxTotalBytes: cfg.MaxTotalBytes,
		now:           cfg.Now,
		logger:        cfg.Logger,
	}, nil
}

func ValidateID(blobID string) bool {
	return blobIDPattern.MatchString(blobID)
}

func (m *Manager) path(blobID string) string {
	return filepath.Join(m.dir, blobID+".bin")
}

func (m *Manager) MaxBlobBytes() int64 {
	return m.maxBlobBytes
}

func (m *Manager) Head(ctx context.Context, blobID string) (*store.BlobMeta, error) {
	if !ValidateID(blobID) {
		return nil, ErrInvalidBlobID
	}

	m.mu.RLock()
	nowMs := m.now().UnixMilli()
	meta, err := m.db.GetBlob(ctx, blobID, nowMs)
	if err != nil {
		m.mu.RUnlock()
		return nil, err
	}
	fi, statErr := os.Stat(m.path(blobID))
	if statErr != nil {
		m.mu.RUnlock()
		if errors.Is(statErr, os.ErrNotExist) {
			m.cleanupMissingRow(ctx, blobID)
			return nil, store.ErrNotFound
		}
		return nil, statErr
	}
	meta.SizeBytes = fi.Size()
	if strings.HasPrefix(blobID, "icon_") {
		newExp := nowMs + m.ttl.Milliseconds()
		if err := m.db.RefreshBlobExpiry(ctx, blobID, newExp); err == nil {
			meta.ExpiresAt = newExp
		}
	}
	m.mu.RUnlock()
	return meta, nil
}

// cleanupMissingRow removes an orphaned DB metadata row only if the file is
// still missing while holding the exclusive write lock (preventing races with Put).
func (m *Manager) cleanupMissingRow(ctx context.Context, blobID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(m.path(blobID)); errors.Is(err, os.ErrNotExist) {
		_ = m.db.DeleteBlob(ctx, blobID)
	}
}

func (m *Manager) Put(ctx context.Context, blobID string, r io.Reader) (*store.BlobMeta, error) {
	if !ValidateID(blobID) {
		return nil, ErrInvalidBlobID
	}
	data, err := io.ReadAll(io.LimitReader(r, m.maxBlobBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read blob body: %w", err)
	}
	if int64(len(data)) > m.maxBlobBytes {
		return nil, ErrBlobTooLarge
	}
	if len(data) == 0 {
		return nil, ErrEmptyBlob
	}

	// Write & fsync temp file before taking m.mu so disk I/O doesn't block readers.
	tmpName, err := m.writeTemp(data)
	if err != nil {
		return nil, err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()

	nowMs := m.now().UnixMilli()
	meta := store.BlobMeta{
		BlobID:    blobID,
		SizeBytes: int64(len(data)),
		CreatedAt: nowMs,
		ExpiresAt: nowMs + m.ttl.Milliseconds(),
	}
	if err := m.db.UpsertBlobWithCommitHook(ctx, meta, func() error {
		if err := os.Rename(tmpName, m.path(blobID)); err != nil {
			return fmt.Errorf("rename blob: %w", err)
		}
		renamed = true
		return nil
	}); err != nil {
		return nil, err
	}

	evicted, err := m.db.EvictBlobsOverLimit(ctx, m.maxTotalBytes, blobID)
	if err != nil {
		m.logger.Warn("blob quota eviction failed", "error", err)
	} else {
		for _, id := range evicted {
			_ = os.Remove(m.path(id))
		}
		if len(evicted) > 0 {
			m.logger.Info("evicted oldest blobs for quota", "count", len(evicted))
		}
	}
	return &meta, nil
}

func (m *Manager) writeTemp(data []byte) (string, error) {
	tmp, err := os.CreateTemp(m.dir, ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp blob: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return "", fmt.Errorf("write temp blob: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("sync temp blob: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp blob: %w", err)
	}
	cleanup = false
	return tmpName, nil
}

func (m *Manager) Get(ctx context.Context, blobID string) (io.ReadCloser, *store.BlobMeta, error) {
	if !ValidateID(blobID) {
		return nil, nil, ErrInvalidBlobID
	}

	m.mu.RLock()
	meta, err := m.db.GetBlob(ctx, blobID, m.now().UnixMilli())
	if err != nil {
		m.mu.RUnlock()
		return nil, nil, err
	}
	f, err := os.Open(m.path(blobID))
	if err != nil {
		m.mu.RUnlock()
		if errors.Is(err, os.ErrNotExist) {
			m.cleanupMissingRow(ctx, blobID)
			return nil, nil, store.ErrNotFound
		}
		return nil, nil, err
	}
	fi, statErr := f.Stat()
	m.mu.RUnlock()
	if statErr != nil {
		_ = f.Close()
		return nil, nil, statErr
	}
	meta.SizeBytes = fi.Size()
	return f, meta, nil
}

func (m *Manager) ReapExpired(ctx context.Context) (eventsDeleted int64, blobsDeleted int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	nowMs := m.now().UnixMilli()
	eventsDeleted, err = m.db.DeleteExpiredOfflineEvents(ctx, nowMs)
	if err != nil {
		return 0, 0, err
	}
	expiredBlobs, err := m.db.DeleteExpiredBlobs(ctx, nowMs)
	if err != nil {
		return eventsDeleted, 0, err
	}
	for _, id := range expiredBlobs {
		_ = os.Remove(m.path(id))
	}
	return eventsDeleted, len(expiredBlobs), nil
}

func (m *Manager) RunReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	reapOnce := func() {
		ev, bl, err := m.ReapExpired(ctx)
		if err != nil {
			if ctx.Err() == nil {
				m.logger.Warn("ttl reaper failed", "error", err)
			}
			return
		}
		if ev > 0 || bl > 0 {
			m.logger.Info("ttl reaper pruned expired records", "offline_events", ev, "blobs", bl)
		}
	}

	reapOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reapOnce()
		}
	}
}
