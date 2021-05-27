package transit

import (
	"context"
	"encoding/base64"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

func (t Transit) Rewrap(ctx context.Context, key, engineName string, req BatchRequestItem) (EncryptBatchResponseItem, error) {
	p, err := t.GetKey(ctx, key, engineName)
	if err != nil {
		return EncryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt get key error", errors.CodePkgCryptoTransitRewrapGetKey)
	}
	if p == nil {
		return EncryptBatchResponseItem{}, errors.Newf(errors.CodePkgCryptoTransitRewrapPolicyNotFound, "transit encrypt missing policy for key %s", key)
	}

	if _, err := base64.StdEncoding.DecodeString(req.Plaintext); err != nil {
		return EncryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt plain text not base64", errors.CodePkgCryptoTransitRewrapPlainTextFormat)
	}

	if len(req.Context) != 0 {
		req.DecodedContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			return EncryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt context not base64", errors.CodePkgCryptoTransitRewrapContextFormat)
		}
	}

	if len(req.Nonce) != 0 {
		var err error
		req.DecodedNonce, err = base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			return EncryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt nonce not base64", errors.CodePkgCryptoTransitRewrapNonceFormat)
		}
	}

	plaintext, err := p.Decrypt(req.DecodedContext, req.DecodedNonce, req.Ciphertext)
	if err != nil {
		return EncryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt policy encrypt error", errors.CodePkgCryptoTransitRewrapDecrypt)
	}

	ciphertext, err := p.Encrypt(req.KeyVersion, req.DecodedContext, req.DecodedNonce, plaintext)
	if err != nil {
		return EncryptBatchResponseItem{}, errors.Wrap(err, "transit encrypt policy encrypt error", errors.CodePkgCryptoTransitRewrapEncrypt)
	}

	if ciphertext == "" {
		return EncryptBatchResponseItem{}, errors.New("empty ciphertext returned for input item", errors.CodePkgCryptoTransitRewrapResultFormat)
	}

	if req.KeyVersion == 0 {
		req.KeyVersion = p.LatestVersion
	}

	return EncryptBatchResponseItem{
		Ciphertext: ciphertext,
		KeyVersion: req.KeyVersion,
	}, nil
}
