package transit

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
)

func (t *Transit) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.u.Storage(req.EngineName),
		Name:    req.KeyName,
	}, rand.Reader)

	if err != nil {
		return nil, errors.Wrap(err, "transit sign get key error", errors.CodePkgCryptoTransitSignGetKey)
	}
	if p == nil {
		return nil, errors.New("transit sign encryption key not found", errors.CodePkgCryptoTransitSignKeyNotFound)
	}

	hashType, err := getVaultHashType(req.HashAlgorithm)
	if err != nil {
		p.Unlock()
		return nil, errors.Wrap(err, "transit sign get hash type error", errors.CodePkgCryptoTransitSignKeyHashType)
	}

	if !p.Type.SigningSupported() {
		p.Unlock()
		return nil, errors.Newf(errors.CodePkgCryptoTransitSignUnsupported, "transit sign key type %v does not support verification", p.Type)
	}

	input, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		p.Unlock()
		return nil, errors.Wrap(err, "transit sign unable to decode input as base64", errors.CodePkgCryptoTransitSignInputFormat)
	}

	if p.Type.HashSignatureInput() && !req.Prehashed {
		hf := keysutil.HashFuncMap[hashType]()
		hf.Write(input)
		input = hf.Sum(nil)
	}

	var verificationContext []byte
	if req.Context != "" {
		verificationContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			p.Unlock()
			return nil, errors.New("transit sign failed to base64-decode context", errors.CodePkgCryptoTransitSignContextFormat)
		}
	}

	sig, err := p.Sign(int(req.KeyVersion), verificationContext, input, hashType, req.SignatureAlgorithm, keysutil.MarshalingTypeASN1)
	p.Unlock()

	if err != nil {
		return nil, errors.Wrap(err, "transit sign error", errors.CodePkgCryptoTransitSign)
	}
	return &structs.SignResponse{
		Result: sig.Signature,
		PubKey: string(sig.PublicKey),
	}, nil
}

func (t *Transit) VerifySign(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.u.Storage(req.EngineName),
		Name:    req.KeyName,
	}, rand.Reader)

	if err != nil {
		return nil, errors.Wrap(err, "transit verify sign get key error", errors.CodePkgCryptoTransitVerifySignGetKey)
	}
	if p == nil {
		return nil, errors.New("transit verify sign encryption key not found", errors.CodePkgCryptoTransitVerifySignKeyNotFound)
	}

	hashType, err := getVaultHashType(req.HashAlgorithm)
	if err != nil {
		return nil, errors.Wrap(err, "transit verify sign get hash type error", errors.CodePkgCryptoTransitVerifySignKeyHashType)
	}
	if !p.Type.SigningSupported() {
		p.Unlock()
		return nil, errors.Newf(errors.CodePkgCryptoTransitVerifySignUnsupported, "transit verify sign key type %v does not support verification", p.Type)
	}

	input, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		p.Unlock()
		return nil, errors.Wrap(err, "transit verify sign unable to decode input as base64", errors.CodePkgCryptoTransitVerifySignInputFormat)
	}

	if p.Type.HashSignatureInput() && !req.Prehashed {
		hf := keysutil.HashFuncMap[hashType]()
		hf.Write(input)
		input = hf.Sum(nil)
	}

	var verificationContext []byte
	if req.Context != "" {
		verificationContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			p.Unlock()
			return nil, errors.New("transit verify sign failed to base64-decode context", errors.CodePkgCryptoTransitVerifySignContextFormat)
		}
	}

	valid, err := p.VerifySignature(verificationContext, input, hashType, req.SignatureAlgorithm, keysutil.MarshalingTypeASN1, req.Signature)
	p.Unlock()

	if err != nil {
		return nil, errors.Wrap(err, "transit sign error", errors.CodePkgCryptoTransitVerifySign)
	}
	return &structs.VerificationResponse{
		VerificationResult: valid,
	}, nil
}

func getVaultHashType(algorithm structs.HashType) (keysutil.HashType, error) {
	var ht keysutil.HashType
	switch algorithm {
	case structs.HashType_HashTypeSHA1:
		ht = keysutil.HashTypeSHA1
	case structs.HashType_HashTypeSHA2224:
		ht = keysutil.HashTypeSHA2224
	case structs.HashType_HashTypeSHA2256:
		ht = keysutil.HashTypeSHA2256
	case structs.HashType_HashTypeSHA2384:
		ht = keysutil.HashTypeSHA2384
	case structs.HashType_HashTypeSHA2512:
		ht = keysutil.HashTypeSHA2512
	default:
		return ht, errors.New("invalid hash algorithm", errors.CodePkgCryptoTransitGetHashType)
	}
	return ht, nil
}
