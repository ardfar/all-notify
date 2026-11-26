package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) CreatePairingCode(ctx context.Context, pc PairingCode, maxPending int, nowMs int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if maxPending > 0 {
		var pending int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pairing_codes
			 WHERE created_by = ? AND claimed_at IS NULL AND cancelled_at IS NULL AND expires_at > ?`,
			pc.CreatedBy, nowMs,
		).Scan(&pending); err != nil {
			return fmt.Errorf("count pending pairing codes: %w", err)
		}
		if pending >= maxPending {
			return ErrTooManyPending
		}
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO pairing_codes (id, code_hash, name, platform, can_add_devices, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		pc.ID, pc.CodeHash, pc.Name, pc.Platform, boolToInt(pc.CanAddDevices), pc.CreatedBy, pc.CreatedAt, pc.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert pairing code: %w", err)
	}
	return tx.Commit()
}

// ClaimPairingCode atomically marks a valid pending code as claimed and creates the device row.
func (s *Store) ClaimPairingCode(
	ctx context.Context,
	codeHash, deviceID, tokenHash, claimedPlatform string,
	nowMs int64,
) (*Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE pairing_codes SET claimed_at = ?
		 WHERE code_hash = ? AND claimed_at IS NULL AND cancelled_at IS NULL AND expires_at > ?`,
		nowMs, codeHash, nowMs,
	)
	if err != nil {
		return nil, fmt.Errorf("claim pairing code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM pairing_codes WHERE code_hash = ?`, codeHash).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return nil, ErrCodeExpiredOrUsed
	}

	var codeID, name, codePlatform string
	var canAddInt int
	if err := tx.QueryRowContext(ctx,
		`SELECT id, name, platform, can_add_devices FROM pairing_codes WHERE code_hash = ?`,
		codeHash,
	).Scan(&codeID, &name, &codePlatform, &canAddInt); err != nil {
		return nil, fmt.Errorf("load claimed pairing code: %w", err)
	}

	platform := codePlatform
	if claimedPlatform != "" {
		platform = claimedPlatform
	}

	dev := Device{
		ID:            deviceID,
		Name:          name,
		Platform:      platform,
		TokenHash:     tokenHash,
		CanAddDevices: canAddInt != 0,
		CreatedAt:     nowMs,
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO devices (id, name, platform, token_hash, can_add_devices, last_seq, created_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?)`,
		dev.ID, dev.Name, dev.Platform, dev.TokenHash, boolToInt(dev.CanAddDevices), dev.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("insert claimed device: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pairing_codes SET claimed_device_id = ? WHERE id = ?`,
		dev.ID, codeID,
	); err != nil {
		return nil, fmt.Errorf("link claimed device: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &dev, nil
}

func (s *Store) ListPairingCodes(ctx context.Context, createdBy string, sinceMs int64) ([]PairingCode, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if createdBy == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, code_hash, name, platform, can_add_devices, created_by, created_at, expires_at, claimed_at, claimed_device_id, cancelled_at
			 FROM pairing_codes WHERE created_at >= ? ORDER BY created_at DESC, id DESC`,
			sinceMs,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, code_hash, name, platform, can_add_devices, created_by, created_at, expires_at, claimed_at, claimed_device_id, cancelled_at
			 FROM pairing_codes WHERE created_by = ? AND created_at >= ? ORDER BY created_at DESC, id DESC`,
			createdBy, sinceMs,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list pairing codes: %w", err)
	}
	defer rows.Close()

	var out []PairingCode
	for rows.Next() {
		var pc PairingCode
		var canAdd int
		var claimedAt, cancelledAt sql.NullInt64
		var claimedDeviceID sql.NullString
		if err := rows.Scan(
			&pc.ID, &pc.CodeHash, &pc.Name, &pc.Platform, &canAdd, &pc.CreatedBy,
			&pc.CreatedAt, &pc.ExpiresAt, &claimedAt, &claimedDeviceID, &cancelledAt,
		); err != nil {
			return nil, err
		}
		pc.CanAddDevices = canAdd != 0
		if claimedAt.Valid {
			v := claimedAt.Int64
			pc.ClaimedAt = &v
		}
		if claimedDeviceID.Valid {
			v := claimedDeviceID.String
			pc.ClaimedDeviceID = &v
		}
		if cancelledAt.Valid {
			v := cancelledAt.Int64
			pc.CancelledAt = &v
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

func (s *Store) CancelPairingCode(ctx context.Context, id string, nowMs int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`UPDATE pairing_codes SET cancelled_at = ?
		 WHERE id = ? AND claimed_at IS NULL AND cancelled_at IS NULL AND expires_at > ?`,
		nowMs, id, nowMs,
	)
	if err != nil {
		return fmt.Errorf("cancel pairing code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM pairing_codes WHERE id = ?`, id).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return ErrCodeExpiredOrUsed
	}
	return tx.Commit()
}

func (s *Store) DeleteOldPairingCodes(ctx context.Context, cutoffMs int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pairing_codes WHERE created_at <= ?`, cutoffMs)
	if err != nil {
		return 0, fmt.Errorf("delete old pairing codes: %w", err)
	}
	return res.RowsAffected()
}

func (s *Store) GetAdminCredential(ctx context.Context) (*AdminCredential, error) {
	var c AdminCredential
	var mustChange int
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash, must_change, updated_at FROM admin_credentials WHERE id = 1`,
	).Scan(&c.PasswordHash, &mustChange, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.MustChange = mustChange != 0
	return &c, nil
}

func (s *Store) EnsureAdminCredential(ctx context.Context, passwordHash string, nowMs int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO admin_credentials (id, password_hash, must_change, updated_at)
		 VALUES (1, ?, 1, ?)`,
		passwordHash, nowMs,
	)
	if err != nil {
		return false, fmt.Errorf("ensure admin credential: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) SetAdminPassword(ctx context.Context, passwordHash string, mustChange bool, nowMs int64, keepSessionHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO admin_credentials (id, password_hash, must_change, updated_at)
		 VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		     password_hash = excluded.password_hash,
		     must_change = excluded.must_change,
		     updated_at = excluded.updated_at`,
		passwordHash, boolToInt(mustChange), nowMs,
	)
	if err != nil {
		return fmt.Errorf("upsert admin credential: %w", err)
	}
	if keepSessionHash == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions`); err != nil {
			return fmt.Errorf("clear admin sessions: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash != ?`, keepSessionHash); err != nil {
			return fmt.Errorf("clear other admin sessions: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) CreateAdminSession(ctx context.Context, sess AdminSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (token_hash, created_at, expires_at) VALUES (?, ?, ?)`,
		sess.TokenHash, sess.CreatedAt, sess.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert admin session: %w", err)
	}
	return nil
}

func (s *Store) TouchAdminSession(ctx context.Context, tokenHash string, nowMs, newExpiresAtMs int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE admin_sessions SET expires_at = ? WHERE token_hash = ? AND expires_at > ?`,
		newExpiresAtMs, tokenHash, nowMs,
	)
	if err != nil {
		return false, fmt.Errorf("touch admin session: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) DeleteAdminSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredAdminSessions(ctx context.Context, nowMs int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at <= ?`, nowMs)
	if err != nil {
		return 0, fmt.Errorf("delete expired admin sessions: %w", err)
	}
	return res.RowsAffected()
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var val string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return val, err
}

func (s *Store) SetSettingIfUnset(ctx context.Context, key, value string) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAlreadySet
	}
	return nil
}
