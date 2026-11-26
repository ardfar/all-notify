package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/all-notify/server/internal/store"
)

type contextKey struct{}

// DeviceLookup abstracts the DB lookup needed by the bearer middleware.
type DeviceLookup interface {
	GetDeviceByTokenHash(ctx context.Context, tokenHash string) (*store.Device, error)
}

func GenerateMasterKey() ([]byte, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("rand master key: %w", err)
	}
	return b, base64.RawURLEncoding.EncodeToString(b), nil
}

func GenerateToken() (raw string, hashHex string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("rand token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashToken(raw), nil
}

// GenerateDeviceID produces a unique, roughly time-ordered device ID matching ^[A-Za-z0-9_-]+$.
func GenerateDeviceID() (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("rand device id: %w", err)
	}
	tsHex := fmt.Sprintf("%012x", time.Now().UnixMilli())
	return "dev_" + tsHex + hex.EncodeToString(rnd[:]), nil
}

func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

func DeviceFromContext(ctx context.Context) (*store.Device, bool) {
	d, ok := ctx.Value(contextKey{}).(*store.Device)
	return d, ok && d != nil
}

func ExtractBearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func Middleware(lookup DeviceLookup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawTok, ok := ExtractBearerToken(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		gotHash := HashToken(rawTok)
		dev, err := lookup.GetDeviceByTokenHash(r.Context(), gotHash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if dev.RevokedAt != nil || subtle.ConstantTimeCompare([]byte(dev.TokenHash), []byte(gotHash)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, dev)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
