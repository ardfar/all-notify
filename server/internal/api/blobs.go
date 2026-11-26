package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/all-notify/server/internal/blobs"
	"github.com/all-notify/server/internal/store"
)

func (s *Server) handleBlobHead(w http.ResponseWriter, r *http.Request) {
	blobID := r.PathValue("blob_id")
	meta, err := s.blobs.Head(r.Context(), blobID)
	if err != nil {
		writeBlobError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(meta.SizeBytes, 10))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request) {
	blobID := r.PathValue("blob_id")
	if !blobs.ValidateID(blobID) {
		http.Error(w, blobs.ErrInvalidBlobID.Error(), http.StatusBadRequest)
		return
	}
	if r.ContentLength > s.blobs.MaxBlobBytes() {
		http.Error(w, "blob exceeds max size", http.StatusRequestEntityTooLarge)
		return
	}
	meta, err := s.blobs.Put(r.Context(), blobID, r.Body)
	if err != nil {
		writeBlobError(w, err)
		return
	}
	s.logger.Info("stored blob", "blob_id", meta.BlobID, "size_bytes", meta.SizeBytes)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request) {
	blobID := r.PathValue("blob_id")
	rc, meta, err := s.blobs.Get(r.Context(), blobID)
	if err != nil {
		writeBlobError(w, err)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(meta.SizeBytes, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

func writeBlobError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, blobs.ErrInvalidBlobID), errors.Is(err, blobs.ErrEmptyBlob):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, blobs.ErrBlobTooLarge):
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
