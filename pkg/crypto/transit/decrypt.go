package transit

import (
	"context"
	"encoding/base64"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

func (t Transit) Decrypt(ctx context.Context, key, engineName string, req BatchRequestItem) (DecryptBatchResponseItem, error) {
	if req.Ciphertext == "" {
		return DecryptBatchResponseItem{}, errors.New("missing ciphertext to decrypt", errors.CodePkgCryptoTransitDecryptCiphertextFormat)
	}

	var err error
	// Decode the context
	if len(req.Context) != 0 {
		req.DecodedContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			return DecryptBatchResponseItem{}, errors.Wrap(err, "transit decrypt decode context not base64", errors.CodePkgCryptoTransitDecryptDecodeContextFormat)
		}
	}

	// Decode the nonce
	if len(req.Nonce) != 0 {
		req.DecodedNonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return DecryptBatchResponseItem{}, errors.Wrap(err, "transit decrypt nonce not base64", errors.CodePkgCryptoTransitDecryptNonceFormat)
		}
	}

	p, err := t.GetKey(ctx, key, engineName)
	if err != nil {
		return DecryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt get key error", errors.CodePkgCryptoTransitDecryptGetKey)
	}
	if p == nil {
		return DecryptBatchResponseItem{}, errors.Newf(errors.CodePkgCryptoTransitDecryptPolicyNotFound, "transit encrypt missing policy for key %s", key)
	}

	plaintext, err := p.Decrypt(req.DecodedContext, req.DecodedNonce, req.Ciphertext)
	if err != nil {
		return DecryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt policy encrypt error", errors.CodePkgCryptoTransitDecrypt)
	}

	return DecryptBatchResponseItem{
		Plaintext: plaintext,
	}, nil
}
