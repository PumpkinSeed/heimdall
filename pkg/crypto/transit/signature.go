package transit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
)

func (t *Transit) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.u.Storage(req.EngineName),
		Name:    req.KeyName,
	}, rand.Reader)

	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("encryption key not found")
	}

	hashType, err := getVaultHashType(req.HashAlgorithm)
	if err != nil {
		p.Unlock()
		return nil, err
	}

	if !p.Type.SigningSupported() {
		p.Unlock()
		return nil, fmt.Errorf("key type %v does not support verification", p.Type)
	}

	input, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		p.Unlock()
		return nil, fmt.Errorf("unable to decode input as base64: %s", err)
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
			return nil, errors.New("failed to base64-decode context")
		}
	}

	sig, err := p.Sign(int(req.KeyVersion), verificationContext, input, hashType, req.SignatureAlgorithm, keysutil.MarshalingTypeASN1)
	p.Unlock()

	if err != nil {
		return nil, err
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
		return nil, err
	}
	if p == nil {
		return nil, errors.New("encryption key not found")
	}

	hashType, err := getVaultHashType(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	if !p.Type.SigningSupported() {
		p.Unlock()
		return nil, fmt.Errorf("key type %v does not support verification", p.Type)
	}

	input, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		p.Unlock()
		return nil, fmt.Errorf("unable to decode input as base64: %s", err)
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
			return nil, errors.New("failed to base64-decode context")
		}
	}

	valid, err := p.VerifySignature(verificationContext, input, hashType, req.SignatureAlgorithm, keysutil.MarshalingTypeASN1, req.Signature)
	p.Unlock()

	if err != nil {
		return nil, err
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
		return ht, errors.New("invalid hash algorithm")
	}
	return ht, nil
}
