package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/all-notify/server/internal/store"
	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16

	MinPasswordLen       = 12
	initialPasswordChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	initialPasswordLen   = 20
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("rand salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	if memory == 0 || iterations == 0 || threads == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false
	}
	wantHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(wantHash) == 0 {
		return false
	}
	gotHash := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(wantHash)))
	return subtle.ConstantTimeCompare(gotHash, wantHash) == 1
}

func GenerateRandomPassword() (string, error) {
	max := big.NewInt(int64(len(initialPasswordChars)))
	out := make([]byte, initialPasswordLen)
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("rand password: %w", err)
		}
		out[i] = initialPasswordChars[n.Int64()]
	}
	return string(out), nil
}

// EnsureInitialPassword creates a first-boot admin credential if none exists,
// printing the generated password exactly once to stdout (the one sanctioned secret log line).
func EnsureInitialPassword(ctx context.Context, st *store.Store, stdout io.Writer, now func() time.Time) (bool, error) {
	if now == nil {
		now = time.Now
	}
	if _, err := st.GetAdminCredential(ctx); err == nil {
		return false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}

	pw, err := GenerateRandomPassword()
	if err != nil {
		return false, err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return false, err
	}
	created, err := st.EnsureAdminCredential(ctx, hash, now().UnixMilli())
	if err != nil {
		return false, err
	}
	if created && stdout != nil {
		fmt.Fprintf(stdout, "ADMIN INITIAL PASSWORD (shown once, change on first login): %s\n", pw)
	}
	return created, nil
}

// ResetPassword replaces the admin password with a fresh random one, sets must_change=1,
// invalidates all admin sessions, and prints the new password once to stdout.
func ResetPassword(ctx context.Context, st *store.Store, stdout io.Writer, now func() time.Time) (string, error) {
	if now == nil {
		now = time.Now
	}
	pw, err := GenerateRandomPassword()
	if err != nil {
		return "", err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	if err := st.SetAdminPassword(ctx, hash, true, now().UnixMilli(), ""); err != nil {
		return "", err
	}
	if stdout != nil {
		fmt.Fprintf(stdout, "ADMIN INITIAL PASSWORD (shown once, change on first login): %s\n", pw)
	}
	return pw, nil
}
