package pairing

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/store"
)

func TestCreateClaimConcurrentRaceAndLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "pair.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	now := time.UnixMilli(1_764_060_000_000)
	svc := New(st, Config{
		TTL: 10 * time.Minute,
		Now: func() time.Time { return now },
	})

	created, err := svc.Create(ctx, CreateRequest{
		Name:          "Pixel 9",
		Platform:      "android",
		CanAddDevices: true,
		CreatedBy:     "admin",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !auth.PairingCodePattern.MatchString(created.Code) {
		t.Fatalf("code %q does not match pattern", created.Code)
	}

	// Concurrent claim race: 16 goroutines race to claim the same one-time code.
	const workers = 16
	var (
		wg        sync.WaitGroup
		succeeded atomic.Int32
		expired   atomic.Int32
		otherErr  atomic.Int32
		winner    *ClaimResult
		mu        sync.Mutex
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := svc.Claim(ctx, created.Code, "android")
			switch {
			case err == nil:
				succeeded.Add(1)
				mu.Lock()
				winner = res
				mu.Unlock()
			case errors.Is(err, ErrCodeExpiredOrUsed):
				expired.Add(1)
			default:
				otherErr.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if succeeded.Load() != 1 || expired.Load() != workers-1 || otherErr.Load() != 0 {
		t.Fatalf("race result: succeeded=%d expired=%d other=%d", succeeded.Load(), expired.Load(), otherErr.Load())
	}
	if winner == nil || winner.Name != "Pixel 9" || !winner.CanAddDevices {
		t.Fatalf("unexpected winner: %+v", winner)
	}

	// Verify the claimed device token authenticates via store.
	dev, err := st.GetDeviceByTokenHash(ctx, auth.HashToken(winner.Token))
	if err != nil || dev.ID != winner.DeviceID {
		t.Fatalf("claimed device lookup failed: dev=%+v err=%v", dev, err)
	}

	// Expiry check.
	c2, err := svc.Create(ctx, CreateRequest{Name: "Mac", Platform: "macos", CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := svc.Claim(ctx, c2.Code, "macos"); !errors.Is(err, ErrCodeExpiredOrUsed) {
		t.Fatalf("expired claim expected ErrCodeExpiredOrUsed, got %v", err)
	}

	// Cancel check.
	c3, err := svc.Create(ctx, CreateRequest{Name: "Win", Platform: "windows", CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Cancel(ctx, c3.CodeID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if _, err := svc.Claim(ctx, c3.Code, "windows"); !errors.Is(err, ErrCodeExpiredOrUsed) {
		t.Fatalf("cancelled claim expected ErrCodeExpiredOrUsed, got %v", err)
	}

	// List statuses check (no raw code exposed in struct).
	list, err := svc.List(ctx, "admin")
	if err != nil || len(list) != 3 {
		t.Fatalf("List: len=%d err=%v", len(list), err)
	}
	statuses := map[string]string{}
	for _, item := range list {
		statuses[item.CodeID] = item.Status
	}
	if statuses[created.CodeID] != "claimed" || statuses[c2.CodeID] != "expired" || statuses[c3.CodeID] != "cancelled" {
		t.Fatalf("unexpected statuses: %+v", statuses)
	}
}
