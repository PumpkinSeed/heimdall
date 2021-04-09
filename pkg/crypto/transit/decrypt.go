package transit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
)

func (t Transit) Decrypt(ctx context.Context, key string, req BatchRequestItem) (DecryptBatchResponseItem, error) {
	if req.Ciphertext == "" {
		return DecryptBatchResponseItem{}, errors.New("missing ciphertext to decrypt")
	}

	var err error
	// Decode the context
	if len(req.Context) != 0 {
		req.DecodedContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			return DecryptBatchResponseItem{}, err
		}
	}

	// Decode the nonce
	if len(req.Nonce) != 0 {
		req.DecodedNonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return DecryptBatchResponseItem{}, err
		}
	}

	p, err := t.GetKey(ctx, key)
	if err != nil {
		return DecryptBatchResponseItem{}, err
	}
	if p == nil {
		return DecryptBatchResponseItem{}, fmt.Errorf("missing policy for key %s", key)
	}

	defer p.Unlock()

	plaintext, err := p.Decrypt(req.DecodedContext, req.DecodedNonce, req.Ciphertext)
	if err != nil {
		return DecryptBatchResponseItem{}, err
	}

	return DecryptBatchResponseItem{
		Plaintext: plaintext,
	}, nil
}
