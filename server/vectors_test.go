package server_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/all-notify/server/internal/auth"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type testVectors struct {
	ProtocolVersion   int               `json:"protocol_version"`
	KDF               kdfVector         `json:"kdf"`
	EventVectors      []eventVector     `json:"event_vectors"`
	BlobVectors       []blobVector      `json:"blob_vectors"`
	PairingURIVectors pairingURIVectors `json:"pairing_uri_vectors"`
}

type kdfVector struct {
	KMasterHex    string `json:"k_master_hex"`
	KMasterB64URL string `json:"k_master_base64url"`
	EventInfo     string `json:"event_info"`
	BlobInfo      string `json:"blob_info"`
	KCVInfo       string `json:"kcv_info"`
	KEventHex     string `json:"k_event_hex"`
	KBlobHex      string `json:"k_blob_hex"`
	KCVHex        string `json:"kcv_hex"`
}

type eventVector struct {
	Name             string `json:"name"`
	EventID          string `json:"event_id"`
	SenderDeviceID   string `json:"sender_device_id"`
	AAD              string `json:"aad"`
	NonceHex         string `json:"nonce_hex"`
	PlaintextUTF8    string `json:"plaintext_utf8"`
	CiphertextB64URL string `json:"ciphertext_base64url"`
	CiphertextHex    string `json:"ciphertext_hex"`
}

type blobVector struct {
	Name          string `json:"name"`
	BlobID        string `json:"blob_id"`
	AAD           string `json:"aad"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type pairingURIVectors struct {
	Valid   []validPairingURI   `json:"valid"`
	Invalid []invalidPairingURI `json:"invalid"`
}

type validPairingURI struct {
	Name     string           `json:"name"`
	URI      string           `json:"uri"`
	Expected expectedPairData `json:"expected"`
}

type expectedPairData struct {
	V          int    `json:"v"`
	URL        string `json:"url"`
	WSURL      string `json:"ws_url"`
	Token      string `json:"token,omitempty"`
	Code       string `json:"code,omitempty"`
	KeyB64URL  string `json:"key_base64url"`
	KeyHex     string `json:"key_hex"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name"`
}

type invalidPairingURI struct {
	Name   string `json:"name"`
	URI    string `json:"uri"`
	Reason string `json:"reason"`
}

func loadProtocolVectors(t *testing.T) testVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "protocol", "test_vectors.json"))
	if err != nil {
		t.Fatalf("read ../protocol/test_vectors.json: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal test_vectors.json: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func deriveHKDF(t *testing.T, kMaster []byte, info string) []byte {
	t.Helper()
	r := hkdf.New(sha256.New, kMaster, nil, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("hkdf %q: %v", info, err)
	}
	return out
}

func TestProtocolVectors(t *testing.T) {
	v := loadProtocolVectors(t)
	if v.ProtocolVersion != 1 {
		t.Fatalf("protocol_version = %d, want 1", v.ProtocolVersion)
	}

	kMaster := mustHex(t, v.KDF.KMasterHex)
	if got := base64.RawURLEncoding.EncodeToString(kMaster); got != v.KDF.KMasterB64URL {
		t.Fatalf("k_master_base64url = %q, want %q", got, v.KDF.KMasterB64URL)
	}
	kEvent := deriveHKDF(t, kMaster, v.KDF.EventInfo)
	kBlob := deriveHKDF(t, kMaster, v.KDF.BlobInfo)
	if hex.EncodeToString(kEvent) != v.KDF.KEventHex {
		t.Fatalf("k_event mismatch")
	}
	if hex.EncodeToString(kBlob) != v.KDF.KBlobHex {
		t.Fatalf("k_blob mismatch")
	}
	if v.KDF.KCVInfo != auth.KCVKDFInfo {
		t.Fatalf("kcv_info = %q, want %q", v.KDF.KCVInfo, auth.KCVKDFInfo)
	}
	kcv, err := auth.ComputeKCV(kMaster)
	if err != nil || kcv != v.KDF.KCVHex {
		t.Fatalf("kcv mismatch: got=%q want=%q err=%v", kcv, v.KDF.KCVHex, err)
	}

	eventAEAD, err := chacha20poly1305.NewX(kEvent)
	if err != nil {
		t.Fatalf("NewX(kEvent): %v", err)
	}
	blobAEAD, err := chacha20poly1305.NewX(kBlob)
	if err != nil {
		t.Fatalf("NewX(kBlob): %v", err)
	}

	for _, ev := range v.EventVectors {
		t.Run("event/"+ev.Name, func(t *testing.T) {
			aad := fmt.Sprintf("v1|%s|%s", ev.EventID, ev.SenderDeviceID)
			if aad != ev.AAD {
				t.Fatalf("aad = %q, want %q", aad, ev.AAD)
			}
			nonce := mustHex(t, ev.NonceHex)
			wire := append(append([]byte(nil), nonce...), eventAEAD.Seal(nil, nonce, []byte(ev.PlaintextUTF8), []byte(aad))...)
			if hex.EncodeToString(wire) != ev.CiphertextHex {
				t.Fatalf("ciphertext_hex mismatch")
			}
			if base64.RawURLEncoding.EncodeToString(wire) != ev.CiphertextB64URL {
				t.Fatalf("ciphertext_base64url mismatch")
			}
			pt, err := eventAEAD.Open(nil, wire[:chacha20poly1305.NonceSizeX], wire[chacha20poly1305.NonceSizeX:], []byte(aad))
			if err != nil || string(pt) != ev.PlaintextUTF8 {
				t.Fatalf("decrypt event failed: err=%v", err)
			}
			if _, err := eventAEAD.Open(nil, wire[:chacha20poly1305.NonceSizeX], wire[chacha20poly1305.NonceSizeX:], []byte(aad+"!")); err == nil {
				t.Fatalf("expected decrypt failure on tampered AAD")
			}
		})
	}

	for _, bv := range v.BlobVectors {
		t.Run("blob/"+bv.Name, func(t *testing.T) {
			aad := fmt.Sprintf("v1|blob|%s", bv.BlobID)
			if aad != bv.AAD {
				t.Fatalf("aad = %q, want %q", aad, bv.AAD)
			}
			nonce := mustHex(t, bv.NonceHex)
			pt := mustHex(t, bv.PlaintextHex)
			wire := append(append([]byte(nil), nonce...), blobAEAD.Seal(nil, nonce, pt, []byte(aad))...)
			if hex.EncodeToString(wire) != bv.CiphertextHex {
				t.Fatalf("blob ciphertext_hex mismatch")
			}
			gotPT, err := blobAEAD.Open(nil, wire[:chacha20poly1305.NonceSizeX], wire[chacha20poly1305.NonceSizeX:], []byte(aad))
			if err != nil || !bytes.Equal(gotPT, pt) {
				t.Fatalf("decrypt blob failed: err=%v", err)
			}
		})
	}

	for _, tc := range v.PairingURIVectors.Valid {
		t.Run("pair/valid/"+tc.Name, func(t *testing.T) {
			got, err := auth.ParsePairingURI(tc.URI)
			if err != nil {
				t.Fatalf("ParsePairingURI failed: %v", err)
			}
			want := auth.PairingData{
				V:          tc.Expected.V,
				URL:        tc.Expected.URL,
				WSURL:      tc.Expected.WSURL,
				Token:      tc.Expected.Token,
				Code:       tc.Expected.Code,
				KeyB64URL:  tc.Expected.KeyB64URL,
				KeyHex:     tc.Expected.KeyHex,
				DeviceID:   tc.Expected.DeviceID,
				DeviceName: tc.Expected.DeviceName,
			}
			if got != want {
				t.Fatalf("parsed = %+v, want %+v", got, want)
			}

			// Round-trip build + parse.
			var built string
			if got.V == 1 {
				built, err = auth.BuildPairingURI(got.URL, got.Token, got.KeyB64URL, got.DeviceID, got.DeviceName)
			} else {
				built, err = auth.BuildPairingURIv2(got.URL, got.Code, got.KeyB64URL, got.DeviceName)
			}
			if err != nil {
				t.Fatalf("BuildPairingURI(v=%d): %v", got.V, err)
			}
			reparsed, err := auth.ParsePairingURI(built)
			if err != nil || reparsed != want {
				t.Fatalf("round-trip mismatch: got=%+v err=%v", reparsed, err)
			}
		})
	}

	for _, tc := range v.PairingURIVectors.Invalid {
		t.Run("pair/invalid/"+tc.Name, func(t *testing.T) {
			if got, err := auth.ParsePairingURI(tc.URI); err == nil {
				t.Fatalf("expected error (%s), got %+v", tc.Reason, got)
			}
		})
	}
}
