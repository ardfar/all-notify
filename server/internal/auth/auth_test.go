package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/all-notify/server/internal/store"
)

type stubLookup struct {
	devices map[string]*store.Device
}

func (s stubLookup) GetDeviceByTokenHash(_ context.Context, hash string) (*store.Device, error) {
	if d, ok := s.devices[hash]; ok {
		return d, nil
	}
	return nil, store.ErrNotFound
}

func TestGeneratorsAndBearerMiddleware(t *testing.T) {
	id, err := GenerateDeviceID()
	if err != nil {
		t.Fatalf("GenerateDeviceID: %v", err)
	}
	if !regexp.MustCompile(`^dev_[0-9a-f]{28}$`).MatchString(id) {
		t.Fatalf("unexpected device id format: %q", id)
	}

	raw, hash, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if hash != HashToken(raw) {
		t.Fatalf("token hash mismatch")
	}

	revokedAt := int64(12345)
	revRaw, revHash, _ := GenerateToken()
	lookup := stubLookup{
		devices: map[string]*store.Device{
			hash:    {ID: id, Name: "Pixel", Platform: "android", TokenHash: hash},
			revHash: {ID: "dev_rev", Name: "Old", Platform: "macos", TokenHash: revHash, RevokedAt: &revokedAt},
		},
	}

	var gotDev *store.Device
	handler := Middleware(lookup, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := DeviceFromContext(r.Context())
		if !ok {
			t.Error("expected device in context")
		}
		gotDev = d
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name   string
		auth   string
		status int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong_scheme", "Basic " + raw, http.StatusUnauthorized},
		{"empty_bearer", "Bearer   ", http.StatusUnauthorized},
		{"unknown_token", "Bearer unknown_token_value", http.StatusUnauthorized},
		{"revoked_token", "Bearer " + revRaw, http.StatusUnauthorized},
		{"valid_bearer", "Bearer " + raw, http.StatusOK},
		{"lowercase_bearer", "bearer " + raw, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDev = nil
			req := httptest.NewRequest(http.MethodGet, "/v1/ws", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if tc.status == http.StatusOK && (gotDev == nil || gotDev.ID != id) {
				t.Fatalf("gotDev = %+v, want %s", gotDev, id)
			}
		})
	}
}
