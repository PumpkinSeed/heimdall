package transit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/errutil"
)

func (t Transit) Encrypt(ctx context.Context, key string, req BatchRequestItem) (EncryptBatchResponseItem, error) {
	p, err := t.GetKey(ctx, key)
	if err != nil {
		return EncryptBatchResponseItem{}, err
	}
	if p == nil {
		return EncryptBatchResponseItem{}, fmt.Errorf("missing policy for key %s", key)
	}

	defer p.Unlock()

	if _, err := base64.StdEncoding.DecodeString(req.Plaintext); err != nil {
		return EncryptBatchResponseItem{}, err
	}

	if len(req.Context) != 0 {
		req.DecodedContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			return EncryptBatchResponseItem{}, err
		}
	}

	if len(req.Nonce) != 0 {
		var err error
		req.DecodedNonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return EncryptBatchResponseItem{}, err
		}
	}

	ciphertext, err := p.Encrypt(req.KeyVersion, req.DecodedContext, req.DecodedNonce, req.Plaintext)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return EncryptBatchResponseItem{}, err
		default:
			return EncryptBatchResponseItem{}, err
		}
	}

	if ciphertext == "" {
		return EncryptBatchResponseItem{}, errors.New("empty ciphertext returned for input item")
	}

	if req.KeyVersion == 0 {
		req.KeyVersion = p.LatestVersion
	}

	return EncryptBatchResponseItem{
		Ciphertext: ciphertext,
		KeyVersion: req.KeyVersion,
	}, nil
}
