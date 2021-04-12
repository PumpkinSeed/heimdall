package mount

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/keyring"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

const CorePath = "core/mounts"

func Mount(ctx context.Context, b logical.Storage, kr *vault.Keyring) (*vault.MountTable, error) {
	mountsData, err := b.Get(ctx, CorePath)
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
	mounts, err := utils.BarrierDecrypt(CorePath, localGCM, mountsData.Value)
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

		mountEntries = append(mountEntries, entry)
	}

	return &vault.MountTable{
		Type:    mountTable.Type,
		Entries: mountEntries,
	}, nil
}