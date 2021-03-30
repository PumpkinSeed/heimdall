package mount

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/keyring"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
)

const coreMountConfigPath = "core/mounts"

func Mount(ctx context.Context, b physical.Backend, kr *vault.Keyring) (*vault.MountTable, error) {
	mountsData, err := b.Get(ctx, coreMountConfigPath)
	if err != nil {
		return nil, err
	}
	if mountsData == nil {
		return nil, errors.New("missing mounts data")
	}

	// Verify the term is always just one
	term := binary.BigEndian.Uint32(mountsData.Value[:4])
	if term != 1 {
		return nil, errors.New("term mis-match")
	}
	localGCM, err := keyring.AeadForTerm(kr, term)
	if err != nil {
		return nil, err
	}

	// Decrypt the barrier init key
	mounts, err := utils.BarrierDecrypt(coreMountConfigPath, localGCM, mountsData.Value)
	defer utils.Memzero(mounts)
	if err != nil {
		return nil, err
	}

	table, err := decodeMountTable(ctx, mounts)
	if err != nil {
		return nil, err
	}

	return table, nil
}

func decodeMountTable(ctx context.Context, raw []byte) (*vault.MountTable, error) {
	// Decode into mount table
	mountTable := new(vault.MountTable)
	if err := jsonutil.DecodeJSON(raw, mountTable); err != nil {
		return nil, err
	}

	// Populate the namespace in memory
	var mountEntries []*vault.MountEntry
	for _, entry := range mountTable.Entries {
		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
		}
		//ns, err := NamespaceByID(ctx, entry.NamespaceID, c)
		//if err != nil {
		//	return nil, err
		//}
		//if ns == nil {
		//	c.logger.Error("namespace on mount entry not found", "namespace_id", entry.NamespaceID, "mount_path", entry.Path, "mount_description", entry.Description)
		//	continue
		//}

		//entry.namespace = ns
		mountEntries = append(mountEntries, entry)
	}

	return &vault.MountTable{
		Type:    mountTable.Type,
		Entries: mountEntries,
	}, nil
}
