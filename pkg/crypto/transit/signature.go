package transit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"golang.org/x/crypto/ed25519"
	"math/big"
	"strconv"
	"strings"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func (t Transit) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.u.Storage(),
		Name:    req.KeyName,
	}, rand.Reader)

	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("encryption key not found")
	}
	if !p.Type.SigningSupported() {
		return nil, fmt.Errorf("message signing not supported for key type %v", p.Type)
	}
	switch {
	case req.KeyVersion == 0:
		req.KeyVersion = int64(p.LatestVersion)
	case req.KeyVersion < 0:
		return nil, errors.New("requested version for signing is negative")
	case req.KeyVersion > int64(p.LatestVersion):
		return nil, errors.New("requested version for signing is higher than the latest key version")
	case p.MinEncryptionVersion > 0 && req.KeyVersion < int64(p.MinEncryptionVersion):
		return nil, errors.New("requested version for signing is less than the minimum encryption key version")
	}

	var sig []byte
	var pubKey []byte
	keyParams, err := safeGetKeyEntry(p, req.KeyVersion)
	if err != nil {
		return nil, err
	}

	switch p.Type {
	case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
		//var curveBits int
		var curve elliptic.Curve
		switch p.Type {
		case keysutil.KeyType_ECDSA_P384:
			//curveBits = 384
			curve = elliptic.P384()
		case keysutil.KeyType_ECDSA_P521:
			//curveBits = 521
			curve = elliptic.P521()
		default:
			//curveBits = 256
			curve = elliptic.P256()
		}

		key := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     keyParams.EC_X,
				Y:     keyParams.EC_Y,
			},
			D: keyParams.EC_D,
		}

		r, s, err := ecdsa.Sign(rand.Reader, key, []byte(req.Input))
		if err != nil {
			return nil, err
		}
		// This is used by openssl and X.509
		sig, err = asn1.Marshal(ecdsaSignature{
			R: r,
			S: s,
		})
		if err != nil {
			return nil, err
		}

	case keysutil.KeyType_ED25519:
		var key ed25519.PrivateKey

		if p.Derived {
			// Derive the key that should be used
			var err error
			key, err = p.GetKey([]byte(req.Context), int(req.KeyVersion), 32)
			if err != nil {
				return nil, errutil.InternalError{Err: fmt.Sprintf("error deriving key: %v", err)}
			}
			pubKey = key.Public().(ed25519.PublicKey)
		} else {
			key = ed25519.PrivateKey(keyParams.Key)
		}

		// Per docs, do not pre-hash ed25519; it does two passes and performs
		// its own hashing
		sig, err = key.Sign(rand.Reader, []byte(req.Input), crypto.Hash(0))
		if err != nil {
			return nil, err
		}

	case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
		key := keyParams.RSAKey

		var algo crypto.Hash
		switch req.HashAlgorithm {
		case structs.HashType_HashTypeSHA1:
			algo = crypto.SHA1
		case structs.HashType_HashTypeSHA2224:
			algo = crypto.SHA224
		case structs.HashType_HashTypeSHA2256:
			algo = crypto.SHA256
		case structs.HashType_HashTypeSHA2384:
			algo = crypto.SHA384
		case structs.HashType_HashTypeSHA2512:
			algo = crypto.SHA512
		default:
			return nil, errors.New("unsupported hash algorithm")
		}

		if req.SignatureAlgorithm == "" {
			req.SignatureAlgorithm = "pss"
		}

		switch req.SignatureAlgorithm {
		case "pss":
			sig, err = rsa.SignPSS(rand.Reader, key, algo, []byte(req.Input), nil)
			if err != nil {
				return nil, err
			}
		case "pkcs1v15":
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, algo, []byte(req.Input))
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported rsa signature algorithm %s", req.SignatureAlgorithm)
		}

	default:
		return nil, fmt.Errorf("unsupported key type %v", p.Type)
	}

	// Convert to base64
	encoded := base64.StdEncoding.EncodeToString(sig)

	return &structs.SignResponse{Result: getVersionPrefix(p, req.KeyVersion) + encoded, PubKey: string(pubKey)}, nil
}

func (t Transit) VerifySign(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	p, _, err := t.lm.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: t.u.Storage(),
		Name:    req.KeyName,
	}, rand.Reader)

	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("encryption key not found")
	}

	if !p.Type.SigningSupported() {
		return nil, fmt.Errorf("message signing not supported for key type %v", p.Type)
	}

	tplParts, err := getTemplateParts(p)
	if err != nil {
		return nil, err
	}

	// Verify the prefix
	if !strings.HasPrefix(req.Signature, tplParts[0]) {
		return nil, errutil.UserError{Err: "invalid signature: no prefix"}
	}

	splitVerSig := strings.SplitN(strings.TrimPrefix(req.Signature, tplParts[0]), tplParts[1], 2)
	if len(splitVerSig) != 2 {
		return nil, errutil.UserError{Err: "invalid signature: wrong number of fields"}
	}

	ver, err := strconv.Atoi(splitVerSig[0])
	if err != nil {
		return nil, errutil.UserError{Err: "invalid signature: version number could not be decoded"}
	}

	if ver > p.LatestVersion {
		return nil, errutil.UserError{Err: "invalid signature: version is too new"}
	}

	if p.MinDecryptionVersion > 0 && ver < p.MinDecryptionVersion {
		return nil, errors.New("ciphertext or signature version is disallowed by policy (too old)")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(splitVerSig[1])
	if err != nil {
		return nil, errutil.UserError{Err: "invalid base64 signature value"}
	}

	switch p.Type {
	case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
		var curve elliptic.Curve
		switch p.Type {
		case keysutil.KeyType_ECDSA_P384:
			curve = elliptic.P384()
		case keysutil.KeyType_ECDSA_P521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}

		var ecdsaSig ecdsaSignature

		rest, err := asn1.Unmarshal(sigBytes, &ecdsaSig)
		if err != nil {
			return nil, errutil.UserError{Err: "supplied signature is invalid"}
		}
		if rest != nil && len(rest) != 0 {
			return nil, errutil.UserError{Err: "supplied signature contains extra data"}
		}

		keyParams, err := safeGetKeyEntry(p, int64(ver))
		if err != nil {
			return nil, err
		}
		key := &ecdsa.PublicKey{
			Curve: curve,
			X:     keyParams.EC_X,
			Y:     keyParams.EC_Y,
		}
		verificationRes := ecdsa.Verify(key, []byte(req.Input), ecdsaSig.R, ecdsaSig.S)
		return &structs.VerificationResponse{VerificationResult: verificationRes}, nil

	case keysutil.KeyType_ED25519:
		var key ed25519.PrivateKey

		if p.Derived {
			// Derive the key that should be used
			var err error
			key, err = p.GetKey([]byte(req.Context), ver, 32)
			if err != nil {
				return nil, fmt.Errorf("error deriving key: %w", err)
			}
		} else {
			key = ed25519.PrivateKey(p.Keys[strconv.Itoa(ver)].Key)
		}

		verificationRes := ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(req.Input), sigBytes)
		return &structs.VerificationResponse{VerificationResult: verificationRes}, nil

	case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
		keyEntry, err := safeGetKeyEntry(p, int64(ver))
		if err != nil {
			return nil, err
		}

		key := keyEntry.RSAKey

		var algo crypto.Hash
		switch req.HashAlgorithm {
		case structs.HashType_HashTypeSHA1:
			algo = crypto.SHA1
		case structs.HashType_HashTypeSHA2224:
			algo = crypto.SHA224
		case structs.HashType_HashTypeSHA2256:
			algo = crypto.SHA256
		case structs.HashType_HashTypeSHA2384:
			algo = crypto.SHA384
		case structs.HashType_HashTypeSHA2512:
			algo = crypto.SHA512
		default:
			return nil, errors.New("unsupported hash algorithm")
		}

		if req.SignatureAlgorithm == "" {
			req.SignatureAlgorithm = "pss"
		}

		switch req.SignatureAlgorithm {
		case "pss":
			err = rsa.VerifyPSS(&key.PublicKey, algo, []byte(req.Input), sigBytes, nil)
		case "pkcs1v15":
			err = rsa.VerifyPKCS1v15(&key.PublicKey, algo, []byte(req.Input), sigBytes)
		default:
			return nil, errutil.InternalError{Err: fmt.Sprintf("unsupported rsa signature algorithm %s", req.SignatureAlgorithm)}
		}
		if err != nil {
			return &structs.VerificationResponse{}, nil
		} else {
			return &structs.VerificationResponse{VerificationResult: true}, nil
		}

	default:
		return nil, fmt.Errorf("unsupported key type %v", p.Type)
	}
}

func safeGetKeyEntry(p *keysutil.Policy, ver int64) (keysutil.KeyEntry, error) {
	keyVerStr := strconv.Itoa(int(ver))
	keyEntry, ok := p.Keys[keyVerStr]
	if !ok {
		return keyEntry, errors.New("no such key version")
	}
	return keyEntry, nil
}

// TODO
func getVersionPrefix(p *keysutil.Policy, ver int64) string {
	return ""
}

// TODO
func getTemplateParts(p *keysutil.Policy) ([]string, error) {
	return []string{""}, nil
}
