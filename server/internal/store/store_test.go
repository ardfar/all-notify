package store

import (
	"context"
	"database/sql"
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

func TestMigrationFromV0PreservesExistingDevices(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v0.db")

	// Create a genuine v0 database (schema.sql only, user_version=0) with an existing device.
	rawDB, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open raw v0 sqlite: %v", err)
	}
	if _, err := rawDB.Exec(schemaSQL); err != nil {
		t.Fatalf("exec v0 schema: %v", err)
	}
	if _, err := rawDB.Exec(
		`INSERT INTO devices (id, name, platform, token_hash, last_seq, created_at)
		 VALUES ('dev_legacy', 'Vivo Phone', 'android', 'legacy_token_hash', 42, 1000)`,
	); err != nil {
		t.Fatalf("insert v0 device: %v", err)
	}
	var uv int
	if err := rawDB.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil || uv != 0 {
		t.Fatalf("expected user_version=0 before migration, got %d err=%v", uv, err)
	}
	_ = rawDB.Close()

	// Reopen via store.Open -> should migrate to user_version=1 cleanly.
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open migrated DB: %v", err)
	}
	defer st.Close()

	if err := st.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil || uv != 1 {
		t.Fatalf("expected user_version=1 after migration, got %d err=%v", uv, err)
	}

	ctx := context.Background()
	dev, err := st.GetDeviceByTokenHash(ctx, "legacy_token_hash")
	if err != nil {
		t.Fatalf("legacy device lookup failed after migration: %v", err)
	}
	if dev.ID != "dev_legacy" || dev.Name != "Vivo Phone" || dev.LastSeq != 42 || dev.CanAddDevices {
		t.Fatalf("unexpected migrated device: %+v", dev)
	}

	// Reopening again must be an idempotent no-op.
	_ = st.Close()
	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen migrated DB: %v", err)
	}
	defer st2.Close()
	if _, err := st2.GetDeviceByTokenHash(ctx, "legacy_token_hash"); err != nil {
		t.Fatalf("legacy device lookup failed on reopen: %v", err)
	}
}

func TestPairingCodeAdminSessionAndSettings(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// Settings: set once, second set fails.
	if err := st.SetSettingIfUnset(ctx, "kcv", "deadbeef"); err != nil {
		t.Fatalf("SetSettingIfUnset: %v", err)
	}
	if err := st.SetSettingIfUnset(ctx, "kcv", "cafebabe"); !errors.Is(err, ErrAlreadySet) {
		t.Fatalf("expected ErrAlreadySet, got %v", err)
	}
	gotKCV, err := st.GetSetting(ctx, "kcv")
	if err != nil || gotKCV != "deadbeef" {
		t.Fatalf("GetSetting = %q err=%v", gotKCV, err)
	}

	// Pairing code create, maxPending limit, claim, reuse failure.
	pc := PairingCode{
		ID:            "pcid_1",
		CodeHash:      "code_hash_1",
		Name:          "Pixel 9",
		Platform:      "android",
		CanAddDevices: true,
		CreatedBy:     "admin",
		CreatedAt:     1000,
		ExpiresAt:     61000,
	}
	if err := st.CreatePairingCode(ctx, pc, 1, 1000); err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}
	if err := st.CreatePairingCode(ctx, PairingCode{
		ID: "pcid_2", CodeHash: "code_hash_2", Name: "X", Platform: "macos", CreatedBy: "admin", CreatedAt: 1001, ExpiresAt: 61001,
	}, 1, 1001); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("expected ErrTooManyPending, got %v", err)
	}

	dev, err := st.ClaimPairingCode(ctx, "code_hash_1", "dev_new", "tok_hash_new", "android", 2000)
	if err != nil {
		t.Fatalf("ClaimPairingCode: %v", err)
	}
	if dev.ID != "dev_new" || dev.Name != "Pixel 9" || !dev.CanAddDevices {
		t.Fatalf("claimed device mismatch: %+v", dev)
	}
	if _, err := st.ClaimPairingCode(ctx, "code_hash_1", "dev_dup", "tok_hash_dup", "android", 2001); !errors.Is(err, ErrCodeExpiredOrUsed) {
		t.Fatalf("second claim expected ErrCodeExpiredOrUsed, got %v", err)
	}
	if _, err := st.ClaimPairingCode(ctx, "missing_hash", "dev_x", "tok_x", "android", 2001); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing code claim expected ErrNotFound, got %v", err)
	}

	// Admin credentials + session invalidation.
	created, err := st.EnsureAdminCredential(ctx, "hash1", 1000)
	if err != nil || !created {
		t.Fatalf("EnsureAdminCredential first: created=%v err=%v", created, err)
	}
	created, err = st.EnsureAdminCredential(ctx, "hash2", 1001)
	if err != nil || created {
		t.Fatalf("EnsureAdminCredential second should not overwrite: created=%v err=%v", created, err)
	}
	_ = st.CreateAdminSession(ctx, AdminSession{TokenHash: "s1", CreatedAt: 1000, ExpiresAt: 5000})
	_ = st.CreateAdminSession(ctx, AdminSession{TokenHash: "s2", CreatedAt: 1000, ExpiresAt: 5000})
	if err := st.SetAdminPassword(ctx, "hash_new", false, 2000, "s1"); err != nil {
		t.Fatalf("SetAdminPassword: %v", err)
	}
	ok1, _ := st.TouchAdminSession(ctx, "s1", 2100, 6000)
	ok2, _ := st.TouchAdminSession(ctx, "s2", 2100, 6000)
	if !ok1 || ok2 {
		t.Fatalf("expected s1 valid and s2 invalidated: ok1=%v ok2=%v", ok1, ok2)
	}
}
