package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
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
	Algorithm     string `json:"algorithm"`
	SaltHex       string `json:"salt_hex"`
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

func loadVectors(t *testing.T) testVectors {
	t.Helper()
	raw, err := os.ReadFile("test_vectors.json")
	if err != nil {
		t.Fatalf("read test_vectors.json: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal test_vectors.json: %v", err)
	}
	return v
}

func deriveKey(t *testing.T, kMaster []byte, info string, length int) []byte {
	t.Helper()
	r := hkdf.New(sha256.New, kMaster, nil, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("hkdf derive %q: %v", info, err)
	}
	return out
}

var pairingCodeRegex = regexp.MustCompile(`^pc_[A-Za-z0-9_-]{22}$`)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

func parsePairingURI(raw string) (expectedPairData, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return expectedPairData{}, fmt.Errorf("parse uri: %w", err)
	}
	if u.Scheme != "allnotify" {
		return expectedPairData{}, errors.New("scheme must be allnotify")
	}
	if u.Host != "pair" {
		return expectedPairData{}, errors.New("host must be pair")
	}
	if u.Path != "" && u.Path != "/" {
		return expectedPairData{}, errors.New("unexpected pairing uri path")
	}
	q := u.Query()
	vStr := q.Get("v")
	if vStr == "" {
		return expectedPairData{}, errors.New("missing v")
	}
	vInt, err := strconv.Atoi(vStr)
	if err != nil || (vInt != 1 && vInt != 2) {
		return expectedPairData{}, errors.New("unsupported version")
	}

	serverURLRaw := q.Get("url")
	if serverURLRaw == "" {
		return expectedPairData{}, errors.New("missing url")
	}
	su, err := url.Parse(serverURLRaw)
	if err != nil || su.Scheme != "https" || su.Hostname() == "" || su.User != nil || su.RawQuery != "" || su.Fragment != "" {
		return expectedPairData{}, errors.New("url must be valid https base url without userinfo, query, or fragment")
	}
	cleanURL := strings.TrimRight(su.String(), "/")
	wsURL := "wss://" + strings.TrimPrefix(cleanURL, "https://") + "/v1/ws"

	deviceName := q.Get("name")
	if deviceName == "" {
		return expectedPairData{}, errors.New("missing name")
	}

	keyB64 := q.Get("key")
	if keyB64 == "" || strings.Contains(keyB64, "=") {
		return expectedPairData{}, errors.New("key must be unpadded base64url")
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil || len(keyBytes) != 32 {
		return expectedPairData{}, errors.New("key must decode to 32 bytes")
	}

	out := expectedPairData{
		V:          vInt,
		URL:        cleanURL,
		WSURL:      wsURL,
		KeyB64URL:  keyB64,
		KeyHex:     hex.EncodeToString(keyBytes),
		DeviceName: deviceName,
	}
	if vInt == 1 {
		token := q.Get("token")
		if token == "" {
			return expectedPairData{}, errors.New("missing token")
		}
		deviceID := q.Get("device_id")
		if deviceID == "" {
			return expectedPairData{}, errors.New("missing device_id")
		}
		out.Token = token
		out.DeviceID = deviceID
	} else {
		if q.Has("token") || q.Has("device_id") {
			return expectedPairData{}, errors.New("v2 pairing uri must not contain token or device_id")
		}
		code := q.Get("code")
		if !pairingCodeRegex.MatchString(code) {
			return expectedPairData{}, errors.New("invalid or missing pairing code")
		}
		out.Code = code
	}
	return out, nil
}

func TestGeneratorDeterminism(t *testing.T) {
	existing, err := os.ReadFile("test_vectors.json")
	if err != nil {
		t.Fatalf("read committed test_vectors.json: %v", err)
	}

	tmpOut := filepath.Join(t.TempDir(), "test_vectors.json")
	cmd := exec.Command("go", "run", "./cmd/genvectors", "-out", tmpOut)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run genvectors: %v\n%s", err, string(out))
	}

	regenerated, err := os.ReadFile(tmpOut)
	if err != nil {
		t.Fatalf("read regenerated file: %v", err)
	}
	if !bytes.Equal(existing, regenerated) {
		t.Fatalf("test_vectors.json differs from genvectors output; run `go run ./cmd/genvectors`")
	}
}

func TestCryptoVectors(t *testing.T) {
	v := loadVectors(t)
	if v.ProtocolVersion != 1 {
		t.Fatalf("protocol_version = %d, want 1", v.ProtocolVersion)
	}

	kMaster := decodeHex(t, v.KDF.KMasterHex)
	if len(kMaster) != 32 {
		t.Fatalf("k_master len = %d, want 32", len(kMaster))
	}
	if gotB64 := base64.RawURLEncoding.EncodeToString(kMaster); gotB64 != v.KDF.KMasterB64URL {
		t.Fatalf("k_master_base64url mismatch: got %q, want %q", gotB64, v.KDF.KMasterB64URL)
	}

	kEvent := deriveKey(t, kMaster, v.KDF.EventInfo, 32)
	kBlob := deriveKey(t, kMaster, v.KDF.BlobInfo, 32)
	kcv := deriveKey(t, kMaster, v.KDF.KCVInfo, 16)

	if got := hex.EncodeToString(kEvent); got != v.KDF.KEventHex {
		t.Fatalf("k_event mismatch: got %s, want %s", got, v.KDF.KEventHex)
	}
	if got := hex.EncodeToString(kBlob); got != v.KDF.KBlobHex {
		t.Fatalf("k_blob mismatch: got %s, want %s", got, v.KDF.KBlobHex)
	}
	if v.KDF.KCVInfo != "all-notify:v1:kcv" {
		t.Fatalf("kcv_info = %q, want all-notify:v1:kcv", v.KDF.KCVInfo)
	}
	if got := hex.EncodeToString(kcv); got != v.KDF.KCVHex || len(got) != 32 {
		t.Fatalf("kcv mismatch: got %s, want %s", got, v.KDF.KCVHex)
	}
	if bytes.Equal(kEvent, kBlob) {
		t.Fatalf("k_event and k_blob must be domain-separated")
	}

	eventAEAD, err := chacha20poly1305.NewX(kEvent)
	if err != nil {
		t.Fatalf("NewX(kEvent): %v", err)
	}
	blobAEAD, err := chacha20poly1305.NewX(kBlob)
	if err != nil {
		t.Fatalf("NewX(kBlob): %v", err)
	}

	if len(v.EventVectors) == 0 {
		t.Fatal("expected at least one event vector")
	}
	for _, ev := range v.EventVectors {
		t.Run("event/"+ev.Name, func(t *testing.T) {
			wantAAD := fmt.Sprintf("v1|%s|%s", ev.EventID, ev.SenderDeviceID)
			if ev.AAD != wantAAD {
				t.Fatalf("aad = %q, want %q", ev.AAD, wantAAD)
			}

			nonce := decodeHex(t, ev.NonceHex)
			wire := make([]byte, len(nonce), len(nonce)+len(ev.PlaintextUTF8)+eventAEAD.Overhead())
			copy(wire, nonce)
			wire = eventAEAD.Seal(wire, nonce, []byte(ev.PlaintextUTF8), []byte(ev.AAD))

			if gotHex := hex.EncodeToString(wire); gotHex != ev.CiphertextHex {
				t.Fatalf("ciphertext_hex mismatch")
			}
			if gotB64 := base64.RawURLEncoding.EncodeToString(wire); gotB64 != ev.CiphertextB64URL {
				t.Fatalf("ciphertext_base64url mismatch")
			}

			// Round-trip decrypt from base64url
			decoded, err := base64.RawURLEncoding.DecodeString(ev.CiphertextB64URL)
			if err != nil {
				t.Fatalf("base64url decode: %v", err)
			}
			pt, err := eventAEAD.Open(nil, decoded[:chacha20poly1305.NonceSizeX], decoded[chacha20poly1305.NonceSizeX:], []byte(ev.AAD))
			if err != nil {
				t.Fatalf("decrypt event: %v", err)
			}
			if string(pt) != ev.PlaintextUTF8 {
				t.Fatalf("decrypted plaintext mismatch")
			}

			// Negative: tampered AAD
			if _, err := eventAEAD.Open(nil, decoded[:chacha20poly1305.NonceSizeX], decoded[chacha20poly1305.NonceSizeX:], []byte(ev.AAD+"x")); err == nil {
				t.Fatalf("expected decrypt failure with tampered AAD")
			}
			// Negative: wrong key (blob key instead of event key)
			if _, err := blobAEAD.Open(nil, decoded[:chacha20poly1305.NonceSizeX], decoded[chacha20poly1305.NonceSizeX:], []byte(ev.AAD)); err == nil {
				t.Fatalf("expected decrypt failure with wrong key")
			}
			// Negative: tampered ciphertext byte
			tampered := append([]byte(nil), decoded...)
			tampered[len(tampered)-1] ^= 0x01
			if _, err := eventAEAD.Open(nil, tampered[:chacha20poly1305.NonceSizeX], tampered[chacha20poly1305.NonceSizeX:], []byte(ev.AAD)); err == nil {
				t.Fatalf("expected decrypt failure with tampered ciphertext")
			}
		})
	}

	if len(v.BlobVectors) == 0 {
		t.Fatal("expected at least one blob vector")
	}
	for _, bv := range v.BlobVectors {
		t.Run("blob/"+bv.Name, func(t *testing.T) {
			wantAAD := fmt.Sprintf("v1|blob|%s", bv.BlobID)
			if bv.AAD != wantAAD {
				t.Fatalf("aad = %q, want %q", bv.AAD, wantAAD)
			}

			nonce := decodeHex(t, bv.NonceHex)
			pt := decodeHex(t, bv.PlaintextHex)
			wire := make([]byte, len(nonce), len(nonce)+len(pt)+blobAEAD.Overhead())
			copy(wire, nonce)
			wire = blobAEAD.Seal(wire, nonce, pt, []byte(bv.AAD))

			if gotHex := hex.EncodeToString(wire); gotHex != bv.CiphertextHex {
				t.Fatalf("blob ciphertext_hex mismatch")
			}

			decoded := decodeHex(t, bv.CiphertextHex)
			gotPT, err := blobAEAD.Open(nil, decoded[:chacha20poly1305.NonceSizeX], decoded[chacha20poly1305.NonceSizeX:], []byte(bv.AAD))
			if err != nil {
				t.Fatalf("decrypt blob: %v", err)
			}
			if !bytes.Equal(gotPT, pt) {
				t.Fatalf("decrypted blob plaintext mismatch")
			}

			// Negative: wrong AAD and wrong key
			if _, err := blobAEAD.Open(nil, decoded[:chacha20poly1305.NonceSizeX], decoded[chacha20poly1305.NonceSizeX:], []byte("v1|blob|wrong")); err == nil {
				t.Fatalf("expected decrypt failure with wrong blob AAD")
			}
			if _, err := eventAEAD.Open(nil, decoded[:chacha20poly1305.NonceSizeX], decoded[chacha20poly1305.NonceSizeX:], []byte(bv.AAD)); err == nil {
				t.Fatalf("expected decrypt failure with wrong key")
			}
		})
	}
}

func TestPairingURIVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.PairingURIVectors.Valid) == 0 || len(v.PairingURIVectors.Invalid) == 0 {
		t.Fatal("expected both valid and invalid pairing URI vectors")
	}

	for _, tc := range v.PairingURIVectors.Valid {
		t.Run("valid/"+tc.Name, func(t *testing.T) {
			got, err := parsePairingURI(tc.URI)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.Expected {
				t.Fatalf("parsed = %+v, want %+v", got, tc.Expected)
			}
		})
	}

	for _, tc := range v.PairingURIVectors.Invalid {
		t.Run("invalid/"+tc.Name, func(t *testing.T) {
			if got, err := parsePairingURI(tc.URI); err == nil {
				t.Fatalf("expected error (%s), but got %+v", tc.Reason, got)
			}
		})
	}
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	sch, err := c.Compile(path)
	if err != nil {
		t.Fatalf("compile schema %s: %v", path, err)
	}
	return sch
}

func unmarshalAny(t *testing.T, raw string) any {
	t.Helper()
	var v any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("unmarshal json: %v\ninput: %s", err, raw)
	}
	return v
}

func TestSchemas(t *testing.T) {
	wsOuter := compileSchema(t, "schemas/ws_outer.schema.json")
	notifPosted := compileSchema(t, "schemas/notification_posted.schema.json")
	notifDismissed := compileSchema(t, "schemas/notification_dismissed.schema.json")

	v := loadVectors(t)

	// 1. Validate every event vector plaintext against its inner schema.
	for _, ev := range v.EventVectors {
		doc := unmarshalAny(t, ev.PlaintextUTF8)
		m := doc.(map[string]any)
		switch m["type"] {
		case "notification.posted":
			if err := notifPosted.Validate(doc); err != nil {
				t.Fatalf("vector %s failed notification_posted schema: %v", ev.Name, err)
			}
		case "notification.dismissed":
			if err := notifDismissed.Validate(doc); err != nil {
				t.Fatalf("vector %s failed notification_dismissed schema: %v", ev.Name, err)
			}
		default:
			t.Fatalf("vector %s has unexpected type %v", ev.Name, m["type"])
		}
	}

	// 2. Validate minimal notification.posted (only required fields).
	minimalPosted := `{
		"type": "notification.posted",
		"notification_uid": "dev_1:1764060000123:01",
		"sender_device_name": "Pixel 9",
		"posted_at": 1764060000123,
		"app": {"package": "com.example.app", "name": "Example"},
		"content": {"title": "", "body": "Hello"}
	}`
	if err := notifPosted.Validate(unmarshalAny(t, minimalPosted)); err != nil {
		t.Fatalf("minimal notification.posted should be valid: %v", err)
	}

	// 3. Validate all 5 valid outer WS frames using real ciphertext from test_vectors.json.
	ct := v.EventVectors[0].CiphertextB64URL
	validOuterFrames := map[string]string{
		"relay":           fmt.Sprintf(`{"op":"relay","event_id":"01JABCDEF1234567890ABCDEFG","target":"broadcast","ciphertext":"%s"}`, ct),
		"event":           fmt.Sprintf(`{"op":"event","seq":4821,"event_id":"01JABCDEF1234567890ABCDEFG","sender_device_id":"dev_01JABCDEF1234567890","server_ts":1764060000123,"ciphertext":"%s"}`, ct),
		"replay_complete": `{"op":"replay_complete","latest_seq":0}`,
		"ack":             `{"op":"ack","seq":4821}`,
		"error":           `{"op":"error","code":"PAYLOAD_TOO_LARGE","message":"event exceeds 64KB limit"}`,
	}
	for name, raw := range validOuterFrames {
		if err := wsOuter.Validate(unmarshalAny(t, raw)); err != nil {
			t.Fatalf("valid ws_outer %s failed: %v", name, err)
		}
	}

	// 4. Negative schema cases that MUST fail validation.
	invalidOuterFrames := map[string]string{
		"unknown_op":          `{"op":"ping"}`,
		"relay_wrong_target":  fmt.Sprintf(`{"op":"relay","event_id":"1","target":"single","ciphertext":"%s"}`, ct),
		"relay_padded_b64":    fmt.Sprintf(`{"op":"relay","event_id":"1","target":"broadcast","ciphertext":"%s="}`, ct),
		"relay_extra_field":   fmt.Sprintf(`{"op":"relay","event_id":"1","target":"broadcast","ciphertext":"%s","extra":1}`, ct),
		"relay_event_id_pipe": fmt.Sprintf(`{"op":"relay","event_id":"evt|inject","target":"broadcast","ciphertext":"%s"}`, ct),
		"event_zero_seq":      fmt.Sprintf(`{"op":"event","seq":0,"event_id":"1","sender_device_id":"dev_1","server_ts":1,"ciphertext":"%s"}`, ct),
		"event_sender_pipe":   fmt.Sprintf(`{"op":"event","seq":1,"event_id":"evt_1","sender_device_id":"dev|inject","server_ts":1,"ciphertext":"%s"}`, ct),
		"replay_negative_seq": `{"op":"replay_complete","latest_seq":-1}`,
		"error_empty_code":    `{"op":"error","code":"","message":"oops"}`,
	}
	for name, raw := range invalidOuterFrames {
		if err := wsOuter.Validate(unmarshalAny(t, raw)); err == nil {
			t.Fatalf("invalid ws_outer %s unexpectedly passed validation", name)
		}
	}

	invalidPosted := map[string]string{
		"attachment_too_wide": `{
			"type":"notification.posted","notification_uid":"u1","sender_device_name":"P","posted_at":1,
			"app":{"package":"a","name":"A"},"content":{"title":"t","body":"b"},
			"attachments":[{"kind":"image","blob_id":"img_12345678","mime":"image/webp","width":801,"height":600,"size_bytes":100,"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]
		}`,
		"attachment_too_large": `{
			"type":"notification.posted","notification_uid":"u1","sender_device_name":"P","posted_at":1,
			"app":{"package":"a","name":"A"},"content":{"title":"t","body":"b"},
			"attachments":[{"kind":"image","blob_id":"img_12345678","mime":"image/webp","width":800,"height":600,"size_bytes":524289,"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]
		}`,
		"bad_icon_blob_id": `{
			"type":"notification.posted","notification_uid":"u1","sender_device_name":"P","posted_at":1,
			"app":{"package":"a","name":"A","icon_blob_id":"../etc/passwd"},"content":{"title":"t","body":"b"}
		}`,
		"icon_blob_id_without_sha256": `{
			"type":"notification.posted","notification_uid":"u1","sender_device_name":"P","posted_at":1,
			"app":{"package":"a","name":"A","icon_blob_id":"icon_e3b0c44298fc1c14"},"content":{"title":"t","body":"b"}
		}`,
		"extra_field": `{
			"type":"notification.posted","notification_uid":"u1","sender_device_name":"P","posted_at":1,
			"app":{"package":"a","name":"A"},"content":{"title":"t","body":"b"},"unknown":true
		}`,
	}
	for name, raw := range invalidPosted {
		if err := notifPosted.Validate(unmarshalAny(t, raw)); err == nil {
			t.Fatalf("invalid notification.posted %s unexpectedly passed validation", name)
		}
	}

	invalidDismissed := map[string]string{
		"empty_uids":     `{"type":"notification.dismissed","notification_uids":[],"dismissed_at":1,"dismissed_by_device_name":"Mac"}`,
		"duplicate_uids": `{"type":"notification.dismissed","notification_uids":["u1","u1"],"dismissed_at":1,"dismissed_by_device_name":"Mac"}`,
		"missing_device": `{"type":"notification.dismissed","notification_uids":["u1"],"dismissed_at":1}`,
	}
	for name, raw := range invalidDismissed {
		if err := notifDismissed.Validate(unmarshalAny(t, raw)); err == nil {
			t.Fatalf("invalid notification.dismissed %s unexpectedly passed validation", name)
		}
	}
}
