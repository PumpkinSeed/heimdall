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
	uuidLen = 16
)


func PersistMounts(ctx context.Context, table *vault.MountTable) error {
	if table == nil {
		table = &vault.MountTable{}
	}
	uuid, _ := generateUUID()
	backendAwareUUID, _ := generateUUID()
	// Create the mount entry
	entry := &vault.MountEntry{
		Table:                 "mounts", // mountTableType - the table it belongs to
		Path:                  "transit/",//CorePath, // Mount Path
		Type:                  "transit", // Logical backend type
		Description:           "description",
		Config:                vault.MountConfig{}, // Configuration related to this mount (but not backend-derived)
		Local:                 false, // Local mounts are not replicated or affected by replication
		SealWrap:              false, // Whether to wrap CSPs
		ExternalEntropyAccess: false, // Whether to allow external entropy source access
		Options:               map[string]string{}, // Backend options

		UUID: uuid,
		BackendAwareUUID: backendAwareUUID,
		NamespaceID: "root",
	}

	accessor, err :=  generateMountAccessor(entry.Type)
	if err != nil {
		return err
	}
	entry.Accessor = accessor


	// Sync values to the cache
	entry.SyncCache()

	// TODO
	//viewPath := entry.ViewPath()
	//view := vault.NewBarrierView(unseal.Get().SecurityBarrier, viewPath)
	// preprocessMount



	nonLocalMounts := &vault.MountTable{
		Type: mountTablePath,
	}

	for _, entry := range table.Entries {
		if !entry.Local {
			nonLocalMounts.Entries = append(nonLocalMounts.Entries, entry)
		}
	}

	// TODO lock

	writeTable := func(mt *vault.MountTable, path string) ([]byte, error) {
		barrier := unseal.Get().SecurityBarrier

		// Encode the mount table into JSON and compress it (lzw).
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(mt, nil)
		if err != nil {
			return nil, err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   path,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := barrier.Put(ctx, entry); err != nil {
			return nil, err
		}
		return compressedBytes, nil
	}

	_, err = writeTable(nonLocalMounts, "core/mounts")
	if err != nil {
		return err
	}
	return nil
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
	//for {
	randBytes, err := uuid.GenerateRandomBytes(4)
	if err != nil {
		return "", err
	}
	accessor = fmt.Sprintf("%s_%s", entryType, fmt.Sprintf("%08x", randBytes[0:4]))
	//if entry := c.router.MatchingMountByAccessor(accessor); entry == nil {
	//	break
	//}
	//}

	return accessor, nil
}
