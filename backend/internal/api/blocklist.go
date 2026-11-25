package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"local/esp32-sinkhole/backend/internal/store"
	"local/esp32-sinkhole/backend/internal/telemetry"
)

const maxBlocklistImageBytes = 0x160000

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var crc32Pattern = regexp.MustCompile(`^[0-9a-f]{8}$`)

type publishedBlocklist struct {
	Available    bool      `json:"available"`
	RequestID    string    `json:"request_id"`
	Version      string    `json:"version"`
	ImageSHA256  string    `json:"image_sha256"`
	PayloadCRC32 string    `json:"payload_crc32"`
	ImageBytes   int64     `json:"image_bytes"`
	EntryCount   int64     `json:"entry_count"`
	PublishedAt  time.Time `json:"published_at"`
}

func (s *Server) blocklistManifest(w http.ResponseWriter, r *http.Request) {
	manifest, err := s.readPublishedBlocklist()
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	if err != nil {
		s.logger.Error("read blocklist manifest", "error", err)
		writeError(w, http.StatusServiceUnavailable, "blocklist_update_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}

func (s *Server) blocklistImage(w http.ResponseWriter, r *http.Request) {
	requestedHash := r.PathValue("sha256")
	if !sha256Pattern.MatchString(requestedHash) {
		writeError(w, http.StatusBadRequest, "invalid_image_hash")
		return
	}
	manifest, err := s.readPublishedBlocklist()
	if err != nil || !manifest.Available || manifest.ImageSHA256 != requestedHash {
		writeError(w, http.StatusNotFound, "blocklist_image_not_found")
		return
	}
	imagePath := filepath.Join(s.blocklistDir, "images", requestedHash+".nbl")
	image, err := os.ReadFile(imagePath)
	if err != nil {
		s.logger.Error("read published blocklist image", "error", err)
		writeError(w, http.StatusServiceUnavailable, "blocklist_image_unavailable")
		return
	}
	if err := validatePublishedImage(image, manifest); err != nil {
		s.logger.Error("published blocklist failed validation", "error", err)
		writeError(w, http.StatusServiceUnavailable, "blocklist_image_invalid")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", stringInt(len(image)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Blocklist-SHA256", requestedHash)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(image)
}

func (s *Server) postBlocklistStatus(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var status telemetry.BlocklistUpdateStatus
	if err := decoder.Decode(&status); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := validateBlocklistStatus(status); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := store.UpsertBlocklistUpdateStatus(ctx, s.pool, status); err != nil {
		s.logger.Error("persist blocklist update status", "device_id", status.DeviceID, "error", err)
		writeError(w, http.StatusInternalServerError, "status_persistence_failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) getBlocklistStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	requestID := r.URL.Query().Get("request_id")
	if !validIdentifier(deviceID, 64) || !validIdentifier(requestID, 64) {
		writeError(w, http.StatusBadRequest, "invalid_device_or_request_id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	status, err := store.GetBlocklistUpdateStatus(ctx, s.pool, deviceID, requestID)
	if err == pgx.ErrNoRows {
		writeError(w, http.StatusNotFound, "status_not_found")
		return
	}
	if err != nil {
		s.logger.Error("query blocklist update status", "device_id", deviceID, "error", err)
		writeError(w, http.StatusInternalServerError, "status_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) readPublishedBlocklist() (publishedBlocklist, error) {
	if s.blocklistDir == "" {
		return publishedBlocklist{}, os.ErrNotExist
	}
	data, err := os.ReadFile(filepath.Join(s.blocklistDir, "manifest.json"))
	if err != nil {
		return publishedBlocklist{}, err
	}
	var manifest publishedBlocklist
	if err := json.Unmarshal(data, &manifest); err != nil {
		return publishedBlocklist{}, err
	}
	if !manifest.Available {
		return manifest, nil
	}
	if !validIdentifier(manifest.RequestID, 64) ||
		!validIdentifier(manifest.Version, 96) || !sha256Pattern.MatchString(manifest.ImageSHA256) ||
		!crc32Pattern.MatchString(manifest.PayloadCRC32) ||
		manifest.ImageBytes < 16 || manifest.ImageBytes > maxBlocklistImageBytes ||
		manifest.EntryCount <= 0 || manifest.PublishedAt.IsZero() {
		return publishedBlocklist{}, os.ErrInvalid
	}
	return manifest, nil
}

func validatePublishedImage(image []byte, manifest publishedBlocklist) error {
	if int64(len(image)) != manifest.ImageBytes || len(image) < 16 || len(image) > maxBlocklistImageBytes {
		return io.ErrUnexpectedEOF
	}
	if string(image[:4]) != "NBL1" || image[4] != 1 || image[5] != 1 || image[6] != 5 || image[7] != 0 {
		return os.ErrInvalid
	}
	count := binary.BigEndian.Uint32(image[8:12])
	if int64(count) != manifest.EntryCount || 16+int64(count)*5 != int64(len(image)) {
		return os.ErrInvalid
	}
	imageCRC := binary.BigEndian.Uint32(image[12:16])
	if crc32.ChecksumIEEE(image[16:]) != imageCRC || manifest.PayloadCRC32 != fmt.Sprintf("%08x", imageCRC) {
		return os.ErrInvalid
	}
	digest := sha256.Sum256(image)
	if hex.EncodeToString(digest[:]) != manifest.ImageSHA256 {
		return os.ErrInvalid
	}
	var previous uint64
	for offset := 16; offset < len(image); offset += 5 {
		current := uint64(image[offset])<<32 | uint64(image[offset+1])<<24 |
			uint64(image[offset+2])<<16 | uint64(image[offset+3])<<8 | uint64(image[offset+4])
		if offset > 16 && current <= previous {
			return os.ErrInvalid
		}
		previous = current
	}
	return nil
}

func validateBlocklistStatus(status telemetry.BlocklistUpdateStatus) error {
	if !validIdentifier(status.DeviceID, 64) || !validIdentifier(status.RequestID, 64) {
		return os.ErrInvalid
	}
	switch status.Stage {
	case "ready", "downloading", "writing", "installed", "unchanged", "failed":
	default:
		return os.ErrInvalid
	}
	if status.ImageSHA256 != "" && !sha256Pattern.MatchString(status.ImageSHA256) {
		return os.ErrInvalid
	}
	if status.PayloadCRC32 != "" && !crc32Pattern.MatchString(status.PayloadCRC32) {
		return os.ErrInvalid
	}
	if status.EntryCount < 0 || len(status.Message) > 256 || strings.ContainsAny(status.Message, "\r\n\x00") {
		return os.ErrInvalid
	}
	return nil
}

func stringInt(value int) string {
	return strconv.Itoa(value)
}
