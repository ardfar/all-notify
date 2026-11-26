package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const KCVKDFInfo = "all-notify:v1:kcv"

var PairingCodePattern = regexp.MustCompile(`^pc_[A-Za-z0-9_-]{22}$`)

type PairingData struct {
	V          int
	URL        string
	WSURL      string
	Token      string
	Code       string
	KeyB64URL  string
	KeyHex     string
	DeviceID   string
	DeviceName string
}

func ComputeKCV(kMaster []byte) (string, error) {
	if len(kMaster) != 32 {
		return "", errors.New("k_master must be 32 bytes")
	}
	r := hkdf.New(sha256.New, kMaster, nil, []byte(KCVKDFInfo))
	out := make([]byte, 16)
	if _, err := io.ReadFull(r, out); err != nil {
		return "", err
	}
	return hex.EncodeToString(out), nil
}

func ValidateMasterKeyB64(keyB64 string) ([]byte, error) {
	if keyB64 == "" || strings.Contains(keyB64, "=") {
		return nil, errors.New("key must be unpadded base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil || len(b) != 32 {
		return nil, errors.New("key must be unpadded base64url decoding to 32 bytes")
	}
	return b, nil
}

func NormalizeServerURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("server url is required")
	}
	su, err := url.Parse(raw)
	if err != nil || su.Scheme != "https" || su.Hostname() == "" || su.User != nil || su.RawQuery != "" || su.Fragment != "" {
		return "", errors.New("server url must be a valid https URL without userinfo, query, or fragment")
	}
	return strings.TrimRight(su.String(), "/"), nil
}

func queryEscapeRFC3986(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func BuildPairingURI(serverURL, token, keyB64, deviceID, deviceName string) (string, error) {
	cleanURL, err := NormalizeServerURL(serverURL)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("token is required")
	}
	if _, err := ValidateMasterKeyB64(keyB64); err != nil {
		return "", err
	}
	if deviceID == "" {
		return "", errors.New("device_id is required")
	}
	if deviceName == "" {
		return "", errors.New("name is required")
	}
	return fmt.Sprintf(
		"allnotify://pair?v=1&url=%s&token=%s&key=%s&device_id=%s&name=%s",
		queryEscapeRFC3986(cleanURL),
		queryEscapeRFC3986(token),
		queryEscapeRFC3986(keyB64),
		queryEscapeRFC3986(deviceID),
		queryEscapeRFC3986(deviceName),
	), nil
}

func BuildPairingURIv2(serverURL, code, keyB64, deviceName string) (string, error) {
	cleanURL, err := NormalizeServerURL(serverURL)
	if err != nil {
		return "", err
	}
	if !PairingCodePattern.MatchString(code) {
		return "", errors.New("invalid pairing code")
	}
	if _, err := ValidateMasterKeyB64(keyB64); err != nil {
		return "", err
	}
	if deviceName == "" {
		return "", errors.New("name is required")
	}
	return fmt.Sprintf(
		"allnotify://pair?v=2&url=%s&code=%s&key=%s&name=%s",
		queryEscapeRFC3986(cleanURL),
		queryEscapeRFC3986(code),
		queryEscapeRFC3986(keyB64),
		queryEscapeRFC3986(deviceName),
	), nil
}

func ParsePairingURI(raw string) (PairingData, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return PairingData{}, fmt.Errorf("parse uri: %w", err)
	}
	if u.Scheme != "allnotify" {
		return PairingData{}, errors.New("scheme must be allnotify")
	}
	if u.Host != "pair" {
		return PairingData{}, errors.New("host must be pair")
	}
	if u.Path != "" && u.Path != "/" {
		return PairingData{}, errors.New("unexpected pairing uri path")
	}
	q := u.Query()
	vStr := q.Get("v")
	if vStr == "" {
		return PairingData{}, errors.New("missing v")
	}
	vInt, err := strconv.Atoi(vStr)
	if err != nil || (vInt != 1 && vInt != 2) {
		return PairingData{}, errors.New("unsupported version")
	}

	cleanURL, err := NormalizeServerURL(q.Get("url"))
	if err != nil {
		return PairingData{}, err
	}
	wsURL := "wss://" + strings.TrimPrefix(cleanURL, "https://") + "/v1/ws"

	deviceName := q.Get("name")
	if deviceName == "" {
		return PairingData{}, errors.New("missing name")
	}

	keyB64 := q.Get("key")
	keyBytes, err := ValidateMasterKeyB64(keyB64)
	if err != nil {
		return PairingData{}, err
	}

	out := PairingData{
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
			return PairingData{}, errors.New("missing token")
		}
		deviceID := q.Get("device_id")
		if deviceID == "" {
			return PairingData{}, errors.New("missing device_id")
		}
		out.Token = token
		out.DeviceID = deviceID
	} else {
		if q.Has("token") || q.Has("device_id") {
			return PairingData{}, errors.New("v2 pairing uri must not contain token or device_id")
		}
		code := q.Get("code")
		if !PairingCodePattern.MatchString(code) {
			return PairingData{}, errors.New("invalid or missing pairing code")
		}
		out.Code = code
	}
	return out, nil
}
