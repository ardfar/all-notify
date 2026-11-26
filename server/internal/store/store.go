package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

//go:embed migration_001.sql
var migration001SQL string

const currentSchemaVersion = 1

var (
	ErrNotFound          = errors.New("not found")
	ErrDeviceRevoked     = errors.New("device revoked")
	ErrCodeExpiredOrUsed = errors.New("pairing code expired or already used")
	ErrTooManyPending    = errors.New("too many pending pairing codes")
	ErrAlreadySet        = errors.New("setting already set")
)

type Device struct {
	ID            string
	Name          string
	Platform      string
	TokenHash     string
	CanAddDevices bool
	LastSeq       int64
	CreatedAt     int64
	LastSeen      *int64
	RevokedAt     *int64
}

type PairingCode struct {
	ID              string
	CodeHash        string
	Name            string
	Platform        string
	CanAddDevices   bool
	CreatedBy       string
	CreatedAt       int64
	ExpiresAt       int64
	ClaimedAt       *int64
	ClaimedDeviceID *string
	CancelledAt     *int64
}

type AdminCredential struct {
	PasswordHash string
	MustChange   bool
	UpdatedAt    int64
}

type AdminSession struct {
	TokenHash string
	CreatedAt int64
	ExpiresAt int64
}

type OfflineEvent struct {
	Seq            int64
	RecipientID    string
	EventID        string
	SenderDeviceID string
	Ciphertext     string
	CreatedAt      int64
	ExpiresAt      int64
}

type BlobMeta struct {
	BlobID    string
	SizeBytes int64
	CreatedAt int64
	ExpiresAt int64
}

type Store struct {
	db *sql.DB
}

func Open(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)",
		dbPath,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Single connection keeps pragmas deterministic and avoids SQLITE_BUSY across goroutines.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}
	if version == 0 {
		// Ensure base v0 tables exist (no-op on existing v0 DBs).
		if _, err := db.Exec(schemaSQL); err != nil {
			return fmt.Errorf("apply base schema: %w", err)
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		hasCol, err := tableHasColumn(tx, "devices", "can_add_devices")
		if err != nil {
			return err
		}
		if !hasCol {
			if _, err := tx.Exec(`ALTER TABLE devices ADD COLUMN can_add_devices INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("add devices.can_add_devices: %w", err)
			}
		}
		if _, err := tx.Exec(migration001SQL); err != nil {
			return fmt.Errorf("apply migration 1: %w", err)
		}
		if _, err := tx.Exec(`PRAGMA user_version = 1`); err != nil {
			return fmt.Errorf("set user_version=1: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func tableHasColumn(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) CreateDevice(ctx context.Context, d Device) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (id, name, platform, token_hash, can_add_devices, last_seq, created_at, last_seen, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.Name, d.Platform, d.TokenHash, boolToInt(d.CanAddDevices), d.LastSeq, d.CreatedAt, d.LastSeen, d.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("insert device: %w", err)
	}
	return nil
}

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var canAdd int
	var lastSeen, revokedAt sql.NullInt64
	if err := row.Scan(&d.ID, &d.Name, &d.Platform, &d.TokenHash, &canAdd, &d.LastSeq, &d.CreatedAt, &lastSeen, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	d.CanAddDevices = canAdd != 0
	if lastSeen.Valid {
		v := lastSeen.Int64
		d.LastSeen = &v
	}
	if revokedAt.Valid {
		v := revokedAt.Int64
		d.RevokedAt = &v
	}
	return &d, nil
}

func (s *Store) GetDeviceByTokenHash(ctx context.Context, tokenHash string) (*Device, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, platform, token_hash, can_add_devices, last_seq, created_at, last_seen, revoked_at
		 FROM devices WHERE token_hash = ?`,
		tokenHash,
	)
	return scanDevice(row)
}

func (s *Store) GetDeviceByID(ctx context.Context, id string) (*Device, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, platform, token_hash, can_add_devices, last_seq, created_at, last_seen, revoked_at
		 FROM devices WHERE id = ?`,
		id,
	)
	return scanDevice(row)
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, platform, token_hash, can_add_devices, last_seq, created_at, last_seen, revoked_at
		 FROM devices ORDER BY created_at ASC, id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

func (s *Store) UpdateDevice(ctx context.Context, id string, name *string, canAddDevices *bool) (*Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	dev, err := scanDevice(tx.QueryRowContext(ctx,
		`SELECT id, name, platform, token_hash, can_add_devices, last_seq, created_at, last_seen, revoked_at
		 FROM devices WHERE id = ?`,
		id,
	))
	if err != nil {
		return nil, err
	}
	if dev.RevokedAt != nil {
		return nil, ErrDeviceRevoked
	}
	if name != nil {
		dev.Name = *name
	}
	if canAddDevices != nil {
		dev.CanAddDevices = *canAddDevices
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE devices SET name = ?, can_add_devices = ? WHERE id = ?`,
		dev.Name, boolToInt(dev.CanAddDevices), id,
	); err != nil {
		return nil, fmt.Errorf("update device: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return dev, nil
}

// ListRevokedOrMissing returns any IDs from the provided slice that are revoked or no longer exist.
func (s *Store) ListRevokedOrMissing(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM devices WHERE revoked_at IS NULL AND id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("query active devices: %w", err)
	}
	defer rows.Close()

	active := make(map[string]struct{}, len(ids))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		active[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var revoked []string
	for _, id := range ids {
		if _, ok := active[id]; !ok {
			revoked = append(revoked, id)
		}
	}
	return revoked, nil
}

func (s *Store) RevokeDevice(ctx context.Context, id string, nowMs int64) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		nowMs, id,
	)
	if err != nil {
		return false, fmt.Errorf("revoke device: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM offline_events WHERE recipient_id = ?`, id); err != nil {
		return false, fmt.Errorf("purge revoked queue: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) UpdateDeviceLastSeen(ctx context.Context, id string, nowMs int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE id = ?`, nowMs, id)
	return err
}

func (s *Store) EnqueueForOthers(
	ctx context.Context,
	senderDeviceID, eventID, ciphertext string,
	nowMs, expiresAtMs int64,
) ([]OfflineEvent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var revokedAt sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM devices WHERE id = ?`, senderDeviceID).Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceRevoked
		}
		return nil, err
	}
	if revokedAt.Valid {
		return nil, ErrDeviceRevoked
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM devices WHERE revoked_at IS NULL AND id != ? ORDER BY id ASC`,
		senderDeviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("query recipients: %w", err)
	}
	var recipients []string
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			rows.Close()
			return nil, err
		}
		recipients = append(recipients, rid)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	events := make([]OfflineEvent, 0, len(recipients))
	for _, rid := range recipients {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO offline_events (recipient_id, event_id, sender_device_id, ciphertext, created_at, expires_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			rid, eventID, senderDeviceID, ciphertext, nowMs, expiresAtMs,
		)
		if err != nil {
			return nil, fmt.Errorf("enqueue for %s: %w", rid, err)
		}
		seq, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		events = append(events, OfflineEvent{
			Seq:            seq,
			RecipientID:    rid,
			EventID:        eventID,
			SenderDeviceID: senderDeviceID,
			Ciphertext:     ciphertext,
			CreatedAt:      nowMs,
			ExpiresAt:      expiresAtMs,
		})
	}

	if _, err := tx.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE id = ?`, nowMs, senderDeviceID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Store) QueryOfflineEvents(ctx context.Context, recipientID string, afterSeq, nowMs int64) ([]OfflineEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, recipient_id, event_id, sender_device_id, ciphertext, created_at, expires_at
		 FROM offline_events
		 WHERE recipient_id = ? AND seq > ? AND expires_at > ?
		 ORDER BY seq ASC`,
		recipientID, afterSeq, nowMs,
	)
	if err != nil {
		return nil, fmt.Errorf("query offline events: %w", err)
	}
	defer rows.Close()

	var events []OfflineEvent
	for rows.Next() {
		var ev OfflineEvent
		if err := rows.Scan(
			&ev.Seq, &ev.RecipientID, &ev.EventID, &ev.SenderDeviceID,
			&ev.Ciphertext, &ev.CreatedAt, &ev.ExpiresAt,
		); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

func (s *Store) AckEvents(ctx context.Context, recipientID string, ackSeq, nowMs int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var revokedAt sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM devices WHERE id = ?`, recipientID).Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceRevoked
		}
		return err
	}
	if revokedAt.Valid {
		return ErrDeviceRevoked
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM offline_events WHERE recipient_id = ? AND seq <= ?`,
		recipientID, ackSeq,
	); err != nil {
		return fmt.Errorf("delete acked events: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE devices SET last_seq = MAX(last_seq, ?), last_seen = ? WHERE id = ? AND revoked_at IS NULL`,
		ackSeq, nowMs, recipientID,
	); err != nil {
		return fmt.Errorf("update device cursor: %w", err)
	}
	return tx.Commit()
}

func (s *Store) UpsertBlob(ctx context.Context, m BlobMeta) error {
	return s.UpsertBlobWithCommitHook(ctx, m, nil)
}

// UpsertBlobWithCommitHook upserts blob metadata inside a transaction and runs
// beforeCommit (e.g. atomic temp-file rename) right before committing so a
// canceled context or DB error never touches an existing file on disk.
func (s *Store) UpsertBlobWithCommitHook(ctx context.Context, m BlobMeta, beforeCommit func() error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO blobs (blob_id, size_bytes, created_at, expires_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(blob_id) DO UPDATE SET
		     size_bytes = excluded.size_bytes,
		     created_at = excluded.created_at,
		     expires_at = excluded.expires_at`,
		m.BlobID, m.SizeBytes, m.CreatedAt, m.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("upsert blob: %w", err)
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blob upsert: %w", err)
	}
	return nil
}

func (s *Store) GetBlob(ctx context.Context, blobID string, nowMs int64) (*BlobMeta, error) {
	var m BlobMeta
	err := s.db.QueryRowContext(ctx,
		`SELECT blob_id, size_bytes, created_at, expires_at
		 FROM blobs WHERE blob_id = ? AND expires_at > ?`,
		blobID, nowMs,
	).Scan(&m.BlobID, &m.SizeBytes, &m.CreatedAt, &m.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) RefreshBlobExpiry(ctx context.Context, blobID string, newExpiresAtMs int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE blobs SET expires_at = ? WHERE blob_id = ?`, newExpiresAtMs, blobID)
	return err
}

func (s *Store) DeleteBlob(ctx context.Context, blobID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM blobs WHERE blob_id = ?`, blobID)
	return err
}

func (s *Store) EvictBlobsOverLimit(ctx context.Context, maxBytes int64, keepBlobID string) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var total int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size_bytes), 0) FROM blobs`).Scan(&total); err != nil {
		return nil, err
	}
	if total <= maxBytes {
		return nil, nil
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT blob_id, size_bytes FROM blobs WHERE blob_id != ? ORDER BY created_at ASC, blob_id ASC`,
		keepBlobID,
	)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id   string
		size int64
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.size); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	var evicted []string
	for _, c := range candidates {
		if total <= maxBytes {
			break
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE blob_id = ?`, c.id); err != nil {
			return nil, err
		}
		total -= c.size
		evicted = append(evicted, c.id)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return evicted, nil
}

func (s *Store) DeleteExpiredOfflineEvents(ctx context.Context, nowMs int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM offline_events WHERE expires_at <= ?`, nowMs)
	if err != nil {
		return 0, fmt.Errorf("delete expired offline events: %w", err)
	}
	return res.RowsAffected()
}

func (s *Store) DeleteExpiredBlobs(ctx context.Context, nowMs int64) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT blob_id FROM blobs WHERE expires_at <= ?`, nowMs)
	if err != nil {
		return nil, err
	}
	var expired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		expired = append(expired, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	if len(expired) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE expires_at <= ?`, nowMs); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return expired, nil
}
