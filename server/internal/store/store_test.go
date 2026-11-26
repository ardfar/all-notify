package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPragmasAndDeviceLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	var mode string
	if err := st.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("pragma journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var fk int
	if err := st.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("pragma foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fk)
	}

	if err := st.CreateDevice(ctx, Device{
		ID: "dev_a", Name: "Pixel 9", Platform: "android", TokenHash: "hash_a", CreatedAt: 1000,
	}); err != nil {
		t.Fatalf("create dev_a: %v", err)
	}
	if err := st.CreateDevice(ctx, Device{
		ID: "dev_b", Name: "MacBook", Platform: "macos", TokenHash: "hash_b", CreatedAt: 2000,
	}); err != nil {
		t.Fatalf("create dev_b: %v", err)
	}

	got, err := st.GetDeviceByTokenHash(ctx, "hash_a")
	if err != nil || got.ID != "dev_a" {
		t.Fatalf("GetDeviceByTokenHash: got=%+v err=%v", got, err)
	}
	if _, err := st.GetDeviceByTokenHash(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	list, err := st.ListDevices(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListDevices: len=%d err=%v", len(list), err)
	}

	// Enqueue for others should target only dev_b (no echo to dev_a).
	queued, err := st.EnqueueForOthers(ctx, "dev_a", "evt_1", "ciphertext_payload", 3000, 9000)
	if err != nil {
		t.Fatalf("EnqueueForOthers: %v", err)
	}
	if len(queued) != 1 || queued[0].RecipientID != "dev_b" {
		t.Fatalf("unexpected queued slice: %+v", queued)
	}

	// Revoke dev_b -> marks revoked and purges its queued events.
	ok, err := st.RevokeDevice(ctx, "dev_b", 4000)
	if err != nil || !ok {
		t.Fatalf("RevokeDevice: ok=%v err=%v", ok, err)
	}
	ok, err = st.RevokeDevice(ctx, "dev_b", 4001)
	if err != nil || ok {
		t.Fatalf("second RevokeDevice should return false: ok=%v err=%v", ok, err)
	}

	remaining, err := st.QueryOfflineEvents(ctx, "dev_b", 0, 3500)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("revoked device queue should be empty: len=%d err=%v", len(remaining), err)
	}

	// Revoked sender cannot enqueue or ack.
	if _, err := st.EnqueueForOthers(ctx, "dev_b", "evt_2", "ct", 5000, 9000); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("expected ErrDeviceRevoked on enqueue, got %v", err)
	}
	if err := st.AckEvents(ctx, "dev_b", 99, 5000); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("expected ErrDeviceRevoked on ack, got %v", err)
	}
	revDev, err := st.GetDeviceByID(ctx, "dev_b")
	if err != nil || revDev.LastSeq != 0 {
		t.Fatalf("revoked device last_seq should remain 0, got %+v err=%v", revDev, err)
	}

	revokedIDs, err := st.ListRevokedOrMissing(ctx, []string{"dev_a", "dev_b", "dev_ghost"})
	if err != nil {
		t.Fatalf("ListRevokedOrMissing: %v", err)
	}
	if len(revokedIDs) != 2 {
		t.Fatalf("revokedIDs = %v, want [dev_b dev_ghost]", revokedIDs)
	}
}

func TestReplayAckAndExpiry(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_ = st.CreateDevice(ctx, Device{ID: "dev_a", Name: "A", Platform: "android", TokenHash: "ha", CreatedAt: 1})
	_ = st.CreateDevice(ctx, Device{ID: "dev_b", Name: "B", Platform: "macos", TokenHash: "hb", CreatedAt: 2})

	ev1, err := st.EnqueueForOthers(ctx, "dev_a", "e1", "ct1", 1000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	ev2, err := st.EnqueueForOthers(ctx, "dev_a", "e2", "ct2", 2000, 8000)
	if err != nil {
		t.Fatal(err)
	}
	ev3, err := st.EnqueueForOthers(ctx, "dev_a", "e3", "ct3", 3000, 9000)
	if err != nil {
		t.Fatal(err)
	}

	// Query at t=6000 skips expired ev1 (expires_at=5000).
	got, err := st.QueryOfflineEvents(ctx, "dev_b", 0, 6000)
	if err != nil || len(got) != 2 || got[0].EventID != "e2" || got[1].EventID != "e3" {
		t.Fatalf("unexpected replay at t=6000: %+v err=%v", got, err)
	}

	// Ack through ev2.
	if err := st.AckEvents(ctx, "dev_b", ev2[0].Seq, 6500); err != nil {
		t.Fatal(err)
	}
	// Regressing ack (ev1.Seq < ev2.Seq) must not decrease last_seq.
	if err := st.AckEvents(ctx, "dev_b", ev1[0].Seq, 6600); err != nil {
		t.Fatal(err)
	}
	devB, err := st.GetDeviceByID(ctx, "dev_b")
	if err != nil || devB.LastSeq != ev2[0].Seq {
		t.Fatalf("dev_b.LastSeq = %d, want %d (err=%v)", devB.LastSeq, ev2[0].Seq, err)
	}

	got, err = st.QueryOfflineEvents(ctx, "dev_b", 0, 6600)
	if err != nil || len(got) != 1 || got[0].Seq != ev3[0].Seq {
		t.Fatalf("expected only ev3 left, got %+v err=%v", got, err)
	}

	// Expire ev3 at t=9000.
	deleted, err := st.DeleteExpiredOfflineEvents(ctx, 9000)
	if err != nil || deleted != 1 {
		t.Fatalf("DeleteExpiredOfflineEvents = %d, want 1 (err=%v)", deleted, err)
	}
}
