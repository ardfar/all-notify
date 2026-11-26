package pairing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/store"
)

const (
	DefaultTTL           = 10 * time.Minute
	TrustedMaxPending    = 5
	ListHistoryWindow    = 24 * time.Hour
	maxDeviceNameLength  = 128
)

var (
	ErrInvalidInput      = errors.New("invalid input")
	ErrCodeNotFound      = errors.New("pairing code not found")
	ErrCodeExpiredOrUsed = errors.New("pairing code expired or already used")
	ErrTooManyPending    = errors.New("too many pending pairing codes")
)

type Config struct {
	TTL time.Duration
	Now func() time.Time
}

type Service struct {
	store *store.Store
	ttl   time.Duration
	now   func() time.Time
}

type CreateRequest struct {
	Name          string
	Platform      string
	CanAddDevices bool
	CreatedBy     string
	MaxPending    int
}

type CreatedCode struct {
	CodeID        string `json:"code_id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	CanAddDevices bool   `json:"can_add_devices"`
	ExpiresAt     int64  `json:"expires_at"`
}

type CodeSummary struct {
	CodeID          string  `json:"code_id"`
	Name            string  `json:"name"`
	Platform        string  `json:"platform"`
	CanAddDevices   bool    `json:"can_add_devices"`
	Status          string  `json:"status"`
	ClaimedDeviceID *string `json:"claimed_device_id"`
	CreatedAt       int64   `json:"created_at"`
	ExpiresAt       int64   `json:"expires_at"`
}

type ClaimResult struct {
	DeviceID      string `json:"device_id"`
	Token         string `json:"token"`
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	CanAddDevices bool   `json:"can_add_devices"`
}

func New(st *store.Store, cfg Config) *Service {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{
		store: st,
		ttl:   cfg.TTL,
		now:   cfg.Now,
	}
}

func ValidateName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || utf8.RuneCountInString(name) > maxDeviceNameLength {
		return "", fmt.Errorf("%w: name must be 1..%d characters", ErrInvalidInput, maxDeviceNameLength)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: name must not contain control characters", ErrInvalidInput)
		}
	}
	return name, nil
}

func ValidatePlatform(raw string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(raw))
	switch p {
	case "android", "macos", "windows":
		return p, nil
	default:
		return "", fmt.Errorf("%w: platform must be one of android, macos, windows", ErrInvalidInput)
	}
}

func generateCode() (raw string, hashHex string, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("rand pairing code: %w", err)
	}
	raw = "pc_" + base64.RawURLEncoding.EncodeToString(b[:])
	return raw, auth.HashToken(raw), nil
}

func generateCodeID(now time.Time) (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("rand code id: %w", err)
	}
	tsHex := fmt.Sprintf("%012x", now.UnixMilli())
	return "pcid_" + tsHex + hex.EncodeToString(rnd[:]), nil
}

func (s *Service) Create(ctx context.Context, req CreateRequest) (*CreatedCode, error) {
	name, err := ValidateName(req.Name)
	if err != nil {
		return nil, err
	}
	platform, err := ValidatePlatform(req.Platform)
	if err != nil {
		return nil, err
	}
	createdBy := strings.TrimSpace(req.CreatedBy)
	if createdBy == "" {
		return nil, fmt.Errorf("%w: created_by is required", ErrInvalidInput)
	}

	now := s.now()
	nowMs := now.UnixMilli()
	expiresAtMs := nowMs + s.ttl.Milliseconds()

	codeID, err := generateCodeID(now)
	if err != nil {
		return nil, err
	}
	rawCode, codeHash, err := generateCode()
	if err != nil {
		return nil, err
	}

	err = s.store.CreatePairingCode(ctx, store.PairingCode{
		ID:            codeID,
		CodeHash:      codeHash,
		Name:          name,
		Platform:      platform,
		CanAddDevices: req.CanAddDevices,
		CreatedBy:     createdBy,
		CreatedAt:     nowMs,
		ExpiresAt:     expiresAtMs,
	}, req.MaxPending, nowMs)
	if err != nil {
		if errors.Is(err, store.ErrTooManyPending) {
			return nil, ErrTooManyPending
		}
		return nil, err
	}

	return &CreatedCode{
		CodeID:        codeID,
		Code:          rawCode,
		Name:          name,
		Platform:      platform,
		CanAddDevices: req.CanAddDevices,
		ExpiresAt:     expiresAtMs,
	}, nil
}

func (s *Service) Claim(ctx context.Context, rawCode, rawPlatform string) (*ClaimResult, error) {
	code := strings.TrimSpace(rawCode)
	if !auth.PairingCodePattern.MatchString(code) {
		return nil, ErrCodeNotFound
	}
	platform, err := ValidatePlatform(rawPlatform)
	if err != nil {
		return nil, err
	}

	devID, err := auth.GenerateDeviceID()
	if err != nil {
		return nil, err
	}
	rawToken, tokenHash, err := auth.GenerateToken()
	if err != nil {
		return nil, err
	}

	dev, err := s.store.ClaimPairingCode(ctx, auth.HashToken(code), devID, tokenHash, platform, s.now().UnixMilli())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return nil, ErrCodeNotFound
		case errors.Is(err, store.ErrCodeExpiredOrUsed):
			return nil, ErrCodeExpiredOrUsed
		default:
			return nil, err
		}
	}

	return &ClaimResult{
		DeviceID:      dev.ID,
		Token:         rawToken,
		Name:          dev.Name,
		Platform:      dev.Platform,
		CanAddDevices: dev.CanAddDevices,
	}, nil
}

func (s *Service) List(ctx context.Context, createdBy string) ([]CodeSummary, error) {
	nowMs := s.now().UnixMilli()
	sinceMs := nowMs - ListHistoryWindow.Milliseconds()
	rows, err := s.store.ListPairingCodes(ctx, createdBy, sinceMs)
	if err != nil {
		return nil, err
	}
	out := make([]CodeSummary, 0, len(rows))
	for _, r := range rows {
		status := "pending"
		switch {
		case r.ClaimedAt != nil:
			status = "claimed"
		case r.CancelledAt != nil:
			status = "cancelled"
		case r.ExpiresAt <= nowMs:
			status = "expired"
		}
		out = append(out, CodeSummary{
			CodeID:          r.ID,
			Name:            r.Name,
			Platform:        r.Platform,
			CanAddDevices:   r.CanAddDevices,
			Status:          status,
			ClaimedDeviceID: r.ClaimedDeviceID,
			CreatedAt:       r.CreatedAt,
			ExpiresAt:       r.ExpiresAt,
		})
	}
	return out, nil
}

func (s *Service) Cancel(ctx context.Context, codeID string) error {
	id := strings.TrimSpace(codeID)
	if id == "" {
		return ErrCodeNotFound
	}
	err := s.store.CancelPairingCode(ctx, id, s.now().UnixMilli())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrCodeNotFound
	case errors.Is(err, store.ErrCodeExpiredOrUsed):
		return ErrCodeExpiredOrUsed
	default:
		return err
	}
}
