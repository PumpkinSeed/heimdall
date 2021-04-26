package init

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

const (
	mountTablePath = "mounts"
	uuidLen        = 16
)

func persistMounts(ctx context.Context) error {
	uuid, _ := generateUUID()
	backendAwareUUID, _ := generateUUID()

	// Create the mount entry
	entry := &vault.MountEntry{
		Table:                 "mounts",   // mountTableType - the table it belongs to
		Path:                  "transit/", //CorePath, // Mount Path
		Type:                  "transit",  // Logical backend type
		Description:           "",
		Config:                vault.MountConfig{}, // Configuration related to this mount (but not backend-derived)
		Local:                 false,               // Local mounts are not replicated or affected by replication
		SealWrap:              false,               // Whether to wrap CSPs
		ExternalEntropyAccess: false,               // Whether to allow external entropy source access
		Options:               map[string]string{}, // Backend options

		UUID:             uuid,
		BackendAwareUUID: backendAwareUUID,
		NamespaceID:      "root",
	}

	accessor, err := generateMountAccessor(entry.Type)
	if err != nil {
		return err
	}
	entry.Accessor = accessor

	// Sync values to the cache
	entry.SyncCache()

	nonLocalMounts := &vault.MountTable{
		Type:    mountTablePath,
		Entries: []*vault.MountEntry{},
	}
	nonLocalMounts.Entries = append(nonLocalMounts.Entries, entry)

	barrier := unseal.Get().SecurityBarrier

	// Encode the mount table into JSON and compress it (lzw).
	compressedBytes, err := jsonutil.EncodeJSONAndCompress(nonLocalMounts, nil)
	if err != nil {
		return err
	}

	// Create an entry
	mountEntry := &logical.StorageEntry{
		Key:   "core/mounts",
		Value: compressedBytes,
	}

	// Write to the physical backend
	return barrier.Put(ctx, mountEntry)
}

func generateUUID() (string, error) {
	buf, err := uuid.GenerateRandomBytesWithReader(uuidLen, rand.Reader)
	if err != nil {
		return "", err
	}
	return uuid.FormatUUID(buf)
}

func generateMountAccessor(entryType string) (string, error) {
	var accessor string
	randBytes, err := uuid.GenerateRandomBytes(4)
	if err != nil {
		return "", err
	}

	accessor = fmt.Sprintf("%s_%s", entryType, fmt.Sprintf("%08x", randBytes[0:4]))

	return accessor, nil
}
