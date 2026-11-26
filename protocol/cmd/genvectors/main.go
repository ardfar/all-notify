package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	protocolVersion = 1
	eventKDFInfo    = "all-notify:v1:event"
	blobKDFInfo     = "all-notify:v1:blob"
	kcvKDFInfo      = "all-notify:v1:kcv"
)

type TestVectors struct {
	ProtocolVersion   int               `json:"protocol_version"`
	KDF               KDFVector         `json:"kdf"`
	EventVectors      []EventVector     `json:"event_vectors"`
	BlobVectors       []BlobVector      `json:"blob_vectors"`
	PairingURIVectors PairingURIVectors `json:"pairing_uri_vectors"`
}

type KDFVector struct {
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

type EventVector struct {
	Name             string `json:"name"`
	EventID          string `json:"event_id"`
	SenderDeviceID   string `json:"sender_device_id"`
	AAD              string `json:"aad"`
	NonceHex         string `json:"nonce_hex"`
	PlaintextUTF8    string `json:"plaintext_utf8"`
	CiphertextB64URL string `json:"ciphertext_base64url"`
	CiphertextHex    string `json:"ciphertext_hex"`
}

type BlobVector struct {
	Name          string `json:"name"`
	BlobID        string `json:"blob_id"`
	AAD           string `json:"aad"`
	NonceHex      string `json:"nonce_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type PairingURIVectors struct {
	Valid   []ValidPairingURI   `json:"valid"`
	Invalid []InvalidPairingURI `json:"invalid"`
}

type ValidPairingURI struct {
	Name     string           `json:"name"`
	URI      string           `json:"uri"`
	Expected ExpectedPairData `json:"expected"`
}

type ExpectedPairData struct {
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

type InvalidPairingURI struct {
	Name   string `json:"name"`
	URI    string `json:"uri"`
	Reason string `json:"reason"`
}

func deriveKey(kMaster []byte, info string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, kMaster, nil, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func encryptXChaCha20Poly1305(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(nonce), chacha20poly1305.NonceSizeX)
	}
	wire := make([]byte, len(nonce), len(nonce)+len(plaintext)+aead.Overhead())
	copy(wire, nonce)
	return aead.Seal(wire, nonce, plaintext, aad), nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func buildVectors() (TestVectors, error) {
	kMaster := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	kMasterB64 := base64.RawURLEncoding.EncodeToString(kMaster)

	kEvent, err := deriveKey(kMaster, eventKDFInfo, 32)
	if err != nil {
		return TestVectors{}, err
	}
	kBlob, err := deriveKey(kMaster, blobKDFInfo, 32)
	if err != nil {
		return TestVectors{}, err
	}
	kcv, err := deriveKey(kMaster, kcvKDFInfo, 16)
	if err != nil {
		return TestVectors{}, err
	}

	postedPlaintext := `{"type":"notification.posted","notification_uid":"dev_01JABCDEF1234567890:1764060000123:a8f3c1","sender_device_name":"Pixel 9","posted_at":1764060000123,"app":{"package":"com.whatsapp","name":"WhatsApp","icon_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","icon_blob_id":"icon_e3b0c44298fc1c14"},"content":{"title":"Alice","body":"Are we still on for dinner at 7?","sub_text":"2 messages","category":"msg","group_key":"whatsapp:alice"},"attachments":[{"kind":"image","blob_id":"img_01JABCDEF1234567890","mime":"image/webp","width":800,"height":600,"size_bytes":84210,"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]}`

	dismissedPlaintext := `{"type":"notification.dismissed","notification_uids":["dev_01JABCDEF1234567890:1764060000123:a8f3c1","dev_01JXYZ9876543210987:1764060001456:b7e2d0"],"dismissed_at":1764060045000,"dismissed_by_device_name":"MacBook Pro"}`

	eventInputs := []struct {
		name           string
		eventID        string
		senderDeviceID string
		nonceHex       string
		plaintext      string
	}{
		{
			name:           "notification_posted_with_attachment",
			eventID:        "01JABCDEF1234567890ABCDEFG",
			senderDeviceID: "dev_01JABCDEF1234567890",
			nonceHex:       "0102030405060708090a0b0c0d0e0f101112131415161718",
			plaintext:      postedPlaintext,
		},
		{
			name:           "notification_dismissed_multi_uid",
			eventID:        "01JABCDEF1234567890ABCDEFH",
			senderDeviceID: "dev_01JMACBOOKPRO00000001",
			nonceHex:       "2122232425262728292a2b2c2d2e2f303132333435363738",
			plaintext:      dismissedPlaintext,
		},
	}

	eventVectors := make([]EventVector, 0, len(eventInputs))
	for _, in := range eventInputs {
		aad := fmt.Sprintf("v1|%s|%s", in.eventID, in.senderDeviceID)
		wire, err := encryptXChaCha20Poly1305(kEvent, mustHex(in.nonceHex), []byte(in.plaintext), []byte(aad))
		if err != nil {
			return TestVectors{}, err
		}
		eventVectors = append(eventVectors, EventVector{
			Name:             in.name,
			EventID:          in.eventID,
			SenderDeviceID:   in.senderDeviceID,
			AAD:              aad,
			NonceHex:         in.nonceHex,
			PlaintextUTF8:    in.plaintext,
			CiphertextB64URL: base64.RawURLEncoding.EncodeToString(wire),
			CiphertextHex:    hex.EncodeToString(wire),
		})
	}

	blobInputs := []struct {
		name         string
		blobID       string
		nonceHex     string
		plaintextHex string
	}{
		{
			name:         "icon_webp_blob",
			blobID:       "icon_e3b0c44298fc1c14",
			nonceHex:     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7",
			plaintextHex: "524946461a000000574542505650384c0d0000002f0000000000000000000000",
		},
		{
			name:         "image_attachment_blob",
			blobID:       "img_01JABCDEF1234567890",
			nonceHex:     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7",
			plaintextHex: "deadbeef00112233445566778899aabbccddeeff",
		},
	}

	blobVectors := make([]BlobVector, 0, len(blobInputs))
	for _, in := range blobInputs {
		aad := fmt.Sprintf("v1|blob|%s", in.blobID)
		wire, err := encryptXChaCha20Poly1305(kBlob, mustHex(in.nonceHex), mustHex(in.plaintextHex), []byte(aad))
		if err != nil {
			return TestVectors{}, err
		}
		blobVectors = append(blobVectors, BlobVector{
			Name:          in.name,
			BlobID:        in.blobID,
			AAD:           aad,
			NonceHex:      in.nonceHex,
			PlaintextHex:  in.plaintextHex,
			CiphertextHex: hex.EncodeToString(wire),
		})
	}

	urlSafeKey := mustHex("fbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a")
	urlSafeKeyB64 := base64.RawURLEncoding.EncodeToString(urlSafeKey)
	stdBase64Key := base64.RawStdEncoding.EncodeToString(urlSafeKey)

	pairingVectors := PairingURIVectors{
		Valid: []ValidPairingURI{
			{
				Name: "standard_https_uri",
				URI:  fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok_01JABCDEF1234567890&key=%s&device_id=dev_01JABCDEF1234567890&name=Pixel%%209", kMasterB64),
				Expected: ExpectedPairData{
					V:          1,
					URL:        "https://notify.example.com",
					WSURL:      "wss://notify.example.com/v1/ws",
					Token:      "tok_01JABCDEF1234567890",
					KeyB64URL:  kMasterB64,
					KeyHex:     hex.EncodeToString(kMaster),
					DeviceID:   "dev_01JABCDEF1234567890",
					DeviceName: "Pixel 9",
				},
			},
			{
				Name: "custom_port_subpath_and_trailing_slash",
				URI:  fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com%%3A8443%%2Frelay%%2F&token=tok_mac_999&key=%s&device_id=dev_01JMACBOOKPRO00000001&name=Farras%%27s%%20MacBook%%20Pro", kMasterB64),
				Expected: ExpectedPairData{
					V:          1,
					URL:        "https://notify.example.com:8443/relay",
					WSURL:      "wss://notify.example.com:8443/relay/v1/ws",
					Token:      "tok_mac_999",
					KeyB64URL:  kMasterB64,
					KeyHex:     hex.EncodeToString(kMaster),
					DeviceID:   "dev_01JMACBOOKPRO00000001",
					DeviceName: "Farras's MacBook Pro",
				},
			},
			{
				Name: "base64url_key_with_dash_and_underscore",
				URI:  fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok_win_001&key=%s&device_id=dev_01JWINPC000000000001&name=Work%%20PC", urlSafeKeyB64),
				Expected: ExpectedPairData{
					V:          1,
					URL:        "https://notify.example.com",
					WSURL:      "wss://notify.example.com/v1/ws",
					Token:      "tok_win_001",
					KeyB64URL:  urlSafeKeyB64,
					KeyHex:     hex.EncodeToString(urlSafeKey),
					DeviceID:   "dev_01JWINPC000000000001",
					DeviceName: "Work PC",
				},
			},
			{
				Name: "v2_standard_https_uri",
				URI:  fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com&code=pc_AAECAwQFBgcICQoLDA0ODw&key=%s&name=Pixel%%209", kMasterB64),
				Expected: ExpectedPairData{
					V:          2,
					URL:        "https://notify.example.com",
					WSURL:      "wss://notify.example.com/v1/ws",
					Code:       "pc_AAECAwQFBgcICQoLDA0ODw",
					KeyB64URL:  kMasterB64,
					KeyHex:     hex.EncodeToString(kMaster),
					DeviceName: "Pixel 9",
				},
			},
			{
				Name: "v2_custom_port_subpath_and_url_safe_code",
				URI:  fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com%%3A8443%%2Frelay%%2F&code=pc_aB3-_9xYz0123456789_-Q&key=%s&name=Work%%20Mac", urlSafeKeyB64),
				Expected: ExpectedPairData{
					V:          2,
					URL:        "https://notify.example.com:8443/relay",
					WSURL:      "wss://notify.example.com:8443/relay/v1/ws",
					Code:       "pc_aB3-_9xYz0123456789_-Q",
					KeyB64URL:  urlSafeKeyB64,
					KeyHex:     hex.EncodeToString(urlSafeKey),
					DeviceName: "Work Mac",
				},
			},
		},
		Invalid: []InvalidPairingURI{
			{
				Name:   "wrong_scheme",
				URI:    fmt.Sprintf("https://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "scheme must be allnotify",
			},
			{
				Name:   "wrong_host",
				URI:    fmt.Sprintf("allnotify://connect?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "host must be pair",
			},
			{
				Name:   "unexpected_pair_path",
				URI:    fmt.Sprintf("allnotify://pair/extra?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "pairing uri must not include a non-empty path",
			},
			{
				Name:   "unsupported_version",
				URI:    fmt.Sprintf("allnotify://pair?v=3&url=https%%3A%%2F%%2Fnotify.example.com&code=pc_AAECAwQFBgcICQoLDA0ODw&key=%s&name=Phone", kMasterB64),
				Reason: "only protocol versions 1 and 2 are supported",
			},
			{
				Name:   "missing_version",
				URI:    fmt.Sprintf("allnotify://pair?url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "v parameter is required",
			},
			{
				Name:   "insecure_http_url",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=http%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "server url must use https",
			},
			{
				Name:   "url_with_query",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com%%3Ffoo%%3Dbar&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "server url must not contain query parameters",
			},
			{
				Name:   "url_with_fragment",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com%%23frag&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "server url must not contain a fragment",
			},
			{
				Name:   "url_with_userinfo",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fuser%%3Apass%%40notify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "server url must not contain userinfo",
			},
			{
				Name:   "short_key",
				URI:    "allnotify://pair?v=1&url=https%3A%2F%2Fnotify.example.com&token=tok&key=AQIDBA&device_id=dev_1&name=Phone",
				Reason: "decoded key must be exactly 32 bytes",
			},
			{
				Name:   "padded_key",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s=&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "key must be unpadded base64url",
			},
			{
				Name:   "standard_base64_key",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1&name=Phone", url.QueryEscape(stdBase64Key)),
				Reason: "key must use base64url alphabet (- and _), not standard base64 (+ and /)",
			},
			{
				Name:   "missing_token",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&key=%s&device_id=dev_1&name=Phone", kMasterB64),
				Reason: "token parameter is required",
			},
			{
				Name:   "missing_device_id",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&name=Phone", kMasterB64),
				Reason: "device_id parameter is required",
			},
			{
				Name:   "missing_name",
				URI:    fmt.Sprintf("allnotify://pair?v=1&url=https%%3A%%2F%%2Fnotify.example.com&token=tok&key=%s&device_id=dev_1", kMasterB64),
				Reason: "name parameter is required",
			},
			{
				Name:   "v2_with_token",
				URI:    fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com&code=pc_AAECAwQFBgcICQoLDA0ODw&token=tok_1&key=%s&name=Phone", kMasterB64),
				Reason: "v2 pairing uri must not contain token",
			},
			{
				Name:   "v2_with_device_id",
				URI:    fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com&code=pc_AAECAwQFBgcICQoLDA0ODw&device_id=dev_1&key=%s&name=Phone", kMasterB64),
				Reason: "v2 pairing uri must not contain device_id",
			},
			{
				Name:   "v2_missing_code",
				URI:    fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com&key=%s&name=Phone", kMasterB64),
				Reason: "code parameter is required for v2",
			},
			{
				Name:   "v2_malformed_code",
				URI:    fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com&code=pc_short&key=%s&name=Phone", kMasterB64),
				Reason: "code must match ^pc_[A-Za-z0-9_-]{22}$",
			},
			{
				Name:   "v2_missing_name",
				URI:    fmt.Sprintf("allnotify://pair?v=2&url=https%%3A%%2F%%2Fnotify.example.com&code=pc_AAECAwQFBgcICQoLDA0ODw&key=%s", kMasterB64),
				Reason: "name parameter is required",
			},
		},
	}

	return TestVectors{
		ProtocolVersion: protocolVersion,
		KDF: KDFVector{
			Algorithm:     "HKDF-SHA256",
			SaltHex:       "",
			KMasterHex:    hex.EncodeToString(kMaster),
			KMasterB64URL: kMasterB64,
			EventInfo:     eventKDFInfo,
			BlobInfo:      blobKDFInfo,
			KCVInfo:       kcvKDFInfo,
			KEventHex:     hex.EncodeToString(kEvent),
			KBlobHex:      hex.EncodeToString(kBlob),
			KCVHex:        hex.EncodeToString(kcv),
		},
		EventVectors:      eventVectors,
		BlobVectors:       blobVectors,
		PairingURIVectors: pairingVectors,
	}, nil
}

func renderJSON(v TestVectors) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	outPath := flag.String("out", "test_vectors.json", "output path for deterministic test vectors JSON")
	flag.Parse()

	vectors, err := buildVectors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error building vectors: %v\n", err)
		os.Exit(1)
	}
	data, err := renderJSON(vectors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *outPath, len(data))
}
