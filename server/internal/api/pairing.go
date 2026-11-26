package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/all-notify/server/internal/admin"
	"github.com/all-notify/server/internal/auth"
	"github.com/all-notify/server/internal/pairing"
)

const maxPairJSONBodyBytes = 8 * 1024

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func decodeJSONStrict(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxPairJSONBodyBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("trailing json data")
	}
	return nil
}

func (s *Server) handlePairClaim(w http.ResponseWriter, r *http.Request) {
	ip := admin.ClientIP(r, s.trustProxy)
	if !s.claimLimit.Allow(ip) {
		writeJSONError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many pairing claim attempts; try again later")
		return
	}

	var req struct {
		Code     string `json:"code"`
		Platform string `json:"platform"`
	}
	if err := decodeJSONStrict(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body")
		return
	}

	res, err := s.pairing.Claim(r.Context(), req.Code, req.Platform)
	if err != nil {
		switch {
		case errors.Is(err, pairing.ErrInvalidInput):
			writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		case errors.Is(err, pairing.ErrCodeNotFound):
			writeJSONError(w, http.StatusNotFound, "CODE_NOT_FOUND", "pairing code not found")
		case errors.Is(err, pairing.ErrCodeExpiredOrUsed):
			writeJSONError(w, http.StatusGone, "CODE_EXPIRED_OR_USED", "pairing code expired or already used")
		default:
			s.logger.Error("pair claim failed", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to claim pairing code")
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	dev, ok := auth.DeviceFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "device auth required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":       dev.ID,
		"name":            dev.Name,
		"platform":        dev.Platform,
		"can_add_devices": dev.CanAddDevices,
	})
}

func (s *Server) handleDeviceCreatePairingCode(w http.ResponseWriter, r *http.Request) {
	dev, ok := auth.DeviceFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "device auth required")
		return
	}
	if !dev.CanAddDevices {
		writeJSONError(w, http.StatusForbidden, "NOT_TRUSTED", "this device is not allowed to add devices")
		return
	}

	var req struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := decodeJSONStrict(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body")
		return
	}

	created, err := s.pairing.Create(r.Context(), pairing.CreateRequest{
		Name:          req.Name,
		Platform:      req.Platform,
		CanAddDevices: false, // Trusted devices can never grant trust.
		CreatedBy:     dev.ID,
		MaxPending:    pairing.TrustedMaxPending,
	})
	if err != nil {
		switch {
		case errors.Is(err, pairing.ErrInvalidInput):
			writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		case errors.Is(err, pairing.ErrTooManyPending):
			writeJSONError(w, http.StatusTooManyRequests, "TOO_MANY_PENDING", "maximum 5 pending pairing codes per device")
		default:
			s.logger.Error("device create pairing code failed", "device_id", dev.ID, "error", err)
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create pairing code")
		}
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleDeviceListPairingCodes(w http.ResponseWriter, r *http.Request) {
	dev, ok := auth.DeviceFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "device auth required")
		return
	}
	if !dev.CanAddDevices {
		writeJSONError(w, http.StatusForbidden, "NOT_TRUSTED", "this device is not allowed to add devices")
		return
	}

	list, err := s.pairing.List(r.Context(), dev.ID)
	if err != nil {
		s.logger.Error("device list pairing codes failed", "device_id", dev.ID, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list pairing codes")
		return
	}
	writeJSON(w, http.StatusOK, list)
}
