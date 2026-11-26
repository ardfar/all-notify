package blobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/all-notify/server/internal/store"
)

func setupTestBlobs(t *testing.T, maxBlob, maxTotal int64, now *time.Time) (*Manager, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blobDir := filepath.Join(dir, "blobs")
	m, err := New(st, Config{
		Dir:           blobDir,
		TTL:           24 * time.Hour,
		MaxBlobBytes:  maxBlob,
		MaxTotalBytes: maxTotal,
		Now:           func() time.Time { return *now },
	})
	if err != nil {
		t.Fatalf("new blob manager: %v", err)
	}
	return m, st, blobDir
}

func TestBlobValidationAndLimits(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m, _, _ := setupTestBlobs(t, 64, 1024, &now)
	ctx := context.Background()

	badIDs := []string{"", "short", "../etc/passwd", "icon_bad/slash", "icon_space here", string(bytes.Repeat([]byte("a"), 65))}
	for _, id := range badIDs {
		if _, err := m.Put(ctx, id, bytes.NewReader([]byte("hello"))); !errors.Is(err, ErrInvalidBlobID) {
			t.Fatalf("Put(%q) = %v, want ErrInvalidBlobID", id, err)
		}
		if _, err := m.Head(ctx, id); !errors.Is(err, ErrInvalidBlobID) {
			t.Fatalf("Head(%q) = %v, want ErrInvalidBlobID", id, err)
		}
		if _, _, err := m.Get(ctx, id); !errors.Is(err, ErrInvalidBlobID) {
			t.Fatalf("Get(%q) = %v, want ErrInvalidBlobID", id, err)
		}
	}

	if _, err := m.Put(ctx, "img_01234567", bytes.NewReader(nil)); !errors.Is(err, ErrEmptyBlob) {
		t.Fatalf("empty Put = %v, want ErrEmptyBlob", err)
	}
	if _, err := m.Put(ctx, "img_01234567", bytes.NewReader(bytes.Repeat([]byte("x"), 65))); !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("oversize Put = %v, want ErrBlobTooLarge", err)
	}
}

func TestBlobHeadRefreshQuotaAndReaper(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m, st, blobDir := setupTestBlobs(t, 100, 150, &now)
	ctx := context.Background()

	// Put icon_ and img_ blobs (60 bytes each -> 120 bytes total <= 150).
	iconID := "icon_0123456789abcdef"
	imgID := "img_01JABCDEF1234567890"
	iconBytes := bytes.Repeat([]byte{0xAA}, 60)
	imgBytes := bytes.Repeat([]byte{0xBB}, 60)

	metaIcon, err := m.Put(ctx, iconID, bytes.NewReader(iconBytes))
	if err != nil {
		t.Fatalf("Put icon: %v", err)
	}
	now = now.Add(time.Hour)
	metaImg, err := m.Put(ctx, imgID, bytes.NewReader(imgBytes))
	if err != nil {
		t.Fatalf("Put img: %v", err)
	}

	// Advance 5 hours and HEAD both: icon_ TTL must refresh, img_ TTL must stay unchanged.
	now = now.Add(5 * time.Hour)
	headIcon, err := m.Head(ctx, iconID)
	if err != nil {
		t.Fatalf("Head icon: %v", err)
	}
	if headIcon.ExpiresAt <= metaIcon.ExpiresAt {
		t.Fatalf("icon_ expiry should have been refreshed: old=%d new=%d", metaIcon.ExpiresAt, headIcon.ExpiresAt)
	}
	headImg, err := m.Head(ctx, imgID)
	if err != nil {
		t.Fatalf("Head img: %v", err)
	}
	if headImg.ExpiresAt != metaImg.ExpiresAt {
		t.Fatalf("img_ expiry should NOT refresh on HEAD: old=%d new=%d", metaImg.ExpiresAt, headImg.ExpiresAt)
	}

	// GET returns exact bytes.
	rc, _, err := m.Get(ctx, imgID)
	if err != nil {
		t.Fatalf("Get img: %v", err)
	}
	gotBytes, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(gotBytes, imgBytes) {
		t.Fatalf("Get bytes mismatch")
	}

	// Quota eviction: putting a 3rd 60-byte blob pushes total to 180 > 150 -> oldest (iconID) is evicted.
	now = now.Add(time.Minute)
	img2ID := "img_01JABCDEF1234567899"
	if _, err := m.Put(ctx, img2ID, bytes.NewReader(bytes.Repeat([]byte{0xCC}, 60))); err != nil {
		t.Fatalf("Put img2: %v", err)
	}
	if _, err := m.Head(ctx, iconID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("oldest blob %s should have been evicted, got err=%v", iconID, err)
	}
	if _, err := os.Stat(filepath.Join(blobDir, iconID+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("evicted blob file still on disk: %v", err)
	}

	// Advance past imgID expiry (still before img2ID expiry? imgID created at +1h -> expires +25h; img2ID created at +6h1m -> expires +30h1m).
	now = time.Unix(1_700_000_000, 0).Add(26 * time.Hour)
	// Also insert an expired offline event to ensure reaper prunes both tables.
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_a", Name: "A", Platform: "android", TokenHash: "ha", CreatedAt: 1})
	_ = st.CreateDevice(ctx, store.Device{ID: "dev_b", Name: "B", Platform: "macos", TokenHash: "hb", CreatedAt: 2})
	_, _ = st.EnqueueForOthers(ctx, "dev_a", "evt_old", "ct", 1, now.UnixMilli()-1)

	evDel, blDel, err := m.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if evDel != 1 || blDel != 1 {
		t.Fatalf("ReapExpired = (%d events, %d blobs), want (1, 1)", evDel, blDel)
	}
	if _, err := os.Stat(filepath.Join(blobDir, imgID+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reaped blob file still on disk: %v", err)
	}
	// img2ID should still be intact.
	if _, err := m.Head(ctx, img2ID); err != nil {
		t.Fatalf("non-expired blob %s should still exist: %v", img2ID, err)
	}
}

func TestBlobFailedIdempotentPutPreservesExisting(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m, _, _ := setupTestBlobs(t, 1024, 4096, &now)
	ctx := context.Background()

	id := "icon_0123456789abcdef"
	orig := []byte("original-encrypted-icon-bytes")
	if _, err := m.Put(ctx, id, bytes.NewReader(orig)); err != nil {
		t.Fatalf("initial Put: %v", err)
	}

	// Re-upload the same blob_id with an already-canceled context.
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.Put(canceledCtx, id, bytes.NewReader([]byte("replacement-bytes-that-fail"))); err == nil {
		t.Fatalf("expected error on canceled Put")
	}

	// Original blob metadata AND bytes on disk must remain intact.
	rc, meta, err := m.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after failed overwrite: %v", err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, orig) || meta.SizeBytes != int64(len(orig)) {
		t.Fatalf("original blob corrupted: got=%q meta.SizeBytes=%d", string(got), meta.SizeBytes)
	}
}

func TestBlobConcurrentPutGetHeadReap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	m, _, _ := setupTestBlobs(t, 4096, 65536, &now)
	ctx := context.Background()

	id := "icon_concurrent12345"
	if _, err := m.Put(ctx, id, bytes.NewReader(bytes.Repeat([]byte("A"), 128))); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	// Writer goroutine repeatedly overwrites the same blob_id with varying sizes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			size := 64 + (i%7)*128
			if _, err := m.Put(ctx, id, bytes.NewReader(bytes.Repeat([]byte{byte(i)}, size))); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Reader goroutine verifies Get always returns exact meta.SizeBytes matching body length.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			rc, meta, err := m.Get(ctx, id)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					continue
				}
				errCh <- err
				return
			}
			body, readErr := io.ReadAll(rc)
			_ = rc.Close()
			if readErr != nil {
				errCh <- readErr
				return
			}
			if int64(len(body)) != meta.SizeBytes {
				errCh <- errors.New("torn read: body length != meta.SizeBytes")
				return
			}
		}
	}()

	// Concurrent HEAD + Reaper goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			_, _ = m.Head(ctx, id)
			_, _, _ = m.ReapExpired(ctx)
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent blob failure: %v", err)
	}
}
