package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/wrappers/aead"
	"github.com/hashicorp/vault/shamir"
	"google.golang.org/protobuf/proto"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

const (
	threshold = 3

	storedBarrierKeysPath = "core/hsm/barrier-unseal-keys"
)

var (
	tempKeys [][]byte
)

func (c *Crypto) Unseal(ctx context.Context, key string) (structs.UnsealResponse, error) {
	defer cleanTempKeys()
	if len(tempKeys) < threshold {
		rk, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return defaultUnsealResponse(), err
		}
		tempKeys = append(tempKeys, rk)
	}
	if len(tempKeys) == threshold {
		return c.unseal(ctx)
	}
	return structs.UnsealResponse{
		Process:   int32(len(tempKeys)),
		Threshold: threshold,
		Unsealed:  false,
	}, nil
}

func (c *Crypto) unseal(ctx context.Context) (structs.UnsealResponse, error) {
	masterData, err := c.backend.Get(ctx, storedBarrierKeysPath)
	if err != nil {
		return defaultUnsealResponse(), err
	}
	unsealed, err := shamir.Combine(tempKeys)
	if err != nil {
		return defaultUnsealResponse(), err
	}

	w := aead.ShamirWrapper{
		Wrapper: aead.NewWrapper(&wrapping.WrapperOptions{}),
	}
	if err := w.SetAESGCMKeyBytes(unsealed); err != nil {
		return defaultUnsealResponse(), err
	}

	blobInfo := &wrapping.EncryptedBlobInfo{}
	if err := proto.Unmarshal(masterData.Value, blobInfo); err != nil {
		return defaultUnsealResponse(), err
	}

	pt, err := w.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return defaultUnsealResponse(), err
	}

	var keys [][]byte
	if err := json.Unmarshal(pt, &keys); err != nil {
		return defaultUnsealResponse(), err
	}

	c.masterKey = keys[0]

	return structs.UnsealResponse{
		Process:   int32(len(tempKeys)),
		Threshold: threshold,
		Unsealed:  true,
	}, nil
}

func defaultUnsealResponse() structs.UnsealResponse {
	return structs.UnsealResponse{
		Process:   int32(len(tempKeys)),
		Threshold: threshold,
		Unsealed:  false,
	}
}

func cleanTempKeys() {
	if len(tempKeys) >= threshold {
		tempKeys = [][]byte{}
	}
}
