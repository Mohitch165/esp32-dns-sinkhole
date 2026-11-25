package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"testing"
	"time"

	"local/esp32-sinkhole/backend/internal/telemetry"
)

func makeTestBlocklist(hashes ...uint64) []byte {
	payload := make([]byte, len(hashes)*5)
	for index, value := range hashes {
		for byteIndex := 4; byteIndex >= 0; byteIndex-- {
			payload[index*5+byteIndex] = byte(value)
			value >>= 8
		}
	}
	image := make([]byte, 16+len(payload))
	copy(image[:4], "NBL1")
	image[4], image[5], image[6], image[7] = 1, 1, 5, 0
	binary.BigEndian.PutUint32(image[8:12], uint32(len(hashes)))
	binary.BigEndian.PutUint32(image[12:16], crc32.ChecksumIEEE(payload))
	copy(image[16:], payload)
	return image
}

func manifestForImage(image []byte) publishedBlocklist {
	digest := sha256.Sum256(image)
	return publishedBlocklist{
		Available: true, RequestID: "update-1", Version: "hagezi-test",
		ImageSHA256:  hex.EncodeToString(digest[:]),
		PayloadCRC32: hex.EncodeToString(image[12:16]),
		ImageBytes:   int64(len(image)), EntryCount: int64(binary.BigEndian.Uint32(image[8:12])),
		PublishedAt: time.Now().UTC(),
	}
}

func TestValidatePublishedImageAcceptsSortedImage(t *testing.T) {
	image := makeTestBlocklist(3, 9, 100)
	if err := validatePublishedImage(image, manifestForImage(image)); err != nil {
		t.Fatalf("validatePublishedImage returned error: %v", err)
	}
}

func TestValidatePublishedImageRejectsCorruptionAndUnsortedHashes(t *testing.T) {
	image := makeTestBlocklist(3, 9, 100)
	manifest := manifestForImage(image)
	corrupt := append([]byte(nil), image...)
	corrupt[len(corrupt)-1] ^= 0x01
	if err := validatePublishedImage(corrupt, manifest); err == nil {
		t.Fatal("corrupted image was accepted")
	}
	unsorted := makeTestBlocklist(9, 3)
	if err := validatePublishedImage(unsorted, manifestForImage(unsorted)); err == nil {
		t.Fatal("unsorted image was accepted")
	}
}

func TestValidateBlocklistStatusRejectsInvalidFields(t *testing.T) {
	valid := telemetry.BlocklistUpdateStatus{
		DeviceID: "esp32-dns-sinkhole", RequestID: "current", Stage: "ready",
		PayloadCRC32: "0123abcd", EntryCount: 10, UpdatedAt: time.Now(),
	}
	if err := validateBlocklistStatus(valid); err != nil {
		t.Fatalf("valid status was rejected: %v", err)
	}
	valid.Stage = "flashing"
	if err := validateBlocklistStatus(valid); err == nil {
		t.Fatal("unsupported stage was accepted")
	}
}
