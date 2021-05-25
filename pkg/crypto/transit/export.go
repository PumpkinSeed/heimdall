package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
)

const (
	ExportTypeEncryptionKey = "encryption-key"
	ExportTypeSigningKey    = "signing-key"
	ExportTypeHMACKey       = "hmac-key"
)

func (t Transit) Export(ctx context.Context, keyName, engineName, exportType, version string) (map[string]string, error) {
	switch exportType {
	case ExportTypeEncryptionKey:
	case ExportTypeSigningKey:
	case ExportTypeHMACKey:
	default:
		return nil, errors.Newf(errors.Code(-1), "invalid export type: %s", exportType) // TODO
	}

	p, err := t.GetKey(ctx, keyName, engineName)
	if err != nil {
		return nil, err // TODO
	}

	if !p.Exportable {
		return nil, errors.New("key is not exportable", errors.Code(-1)) // TODO
	}

	switch exportType {
	case ExportTypeEncryptionKey:
		if !p.Type.EncryptionSupported() {
			return nil, errors.New("encryption not supported for the key", errors.Code(-1)) // TODO
		}
	case ExportTypeSigningKey:
		if !p.Type.SigningSupported() {
			return nil, errors.New("signing not supported for the key", errors.Code(-1)) // TODO
		}
	}

	retKeys := map[string]string{}
	switch version {
	case "":
		for k, v := range p.Keys {
			exportKey, err := getExportKey(p, &v, exportType)
			if err != nil {
				return nil, err
			}
			retKeys[k] = exportKey
		}

	default:
		var versionValue int
		if version == "latest" {
			versionValue = p.LatestVersion
		} else {
			version = strings.TrimPrefix(version, "v")
			versionValue, err = strconv.Atoi(version)
			if err != nil {
				return nil, errors.New("invalid key version", errors.Code(-1)) // TODO
			}
		}

		if versionValue < p.MinDecryptionVersion {
			return nil, errors.New("version for export is below minimum decryption version", errors.Code(-1)) // TODO
		}
		key, ok := p.Keys[strconv.Itoa(versionValue)]
		if !ok {
			return nil, errors.New("version does not exist or cannot be found", errors.Code(-1)) // TODO
		}

		exportKey, err := getExportKey(p, &key, exportType)
		if err != nil {
			return nil, err // TODO
		}

		retKeys[strconv.Itoa(versionValue)] = exportKey
	}

	return retKeys, nil
}

func getExportKey(policy *keysutil.Policy, key *keysutil.KeyEntry, exportType string) (string, error) {
	if policy == nil {
		return "", errors.New("nil policy provided", errors.Code(-1)) // TODO
	}

	switch exportType {
	case ExportTypeHMACKey:
		return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.HMACKey)), nil

	case ExportTypeEncryptionKey:
		switch policy.Type {
		case keysutil.KeyType_AES128_GCM96, keysutil.KeyType_AES256_GCM96, keysutil.KeyType_ChaCha20_Poly1305:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil

		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
			return encodeRSAPrivateKey(key.RSAKey), nil
		}

	case ExportTypeSigningKey:
		switch policy.Type {
		case keysutil.KeyType_ECDSA_P256, keysutil.KeyType_ECDSA_P384, keysutil.KeyType_ECDSA_P521:
			var curve elliptic.Curve
			switch policy.Type {
			case keysutil.KeyType_ECDSA_P384:
				curve = elliptic.P384()
			case keysutil.KeyType_ECDSA_P521:
				curve = elliptic.P521()
			default:
				curve = elliptic.P256()
			}
			ecKey, err := keyEntryToECPrivateKey(key, curve)
			if err != nil {
				return "", err // TODO
			}
			return ecKey, nil

		case keysutil.KeyType_ED25519:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil

		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
			return encodeRSAPrivateKey(key.RSAKey), nil
		}
	}

	return "", fmt.Errorf("unknown key type %v", policy.Type) // TODO
}

func encodeRSAPrivateKey(key *rsa.PrivateKey) string {
	// When encoding PKCS1, the PEM header should be `RSA PRIVATE KEY`. When Go
	// has PKCS8 encoding support, we may want to change this.
	derBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes)
}

func keyEntryToECPrivateKey(k *keysutil.KeyEntry, curve elliptic.Curve) (string, error) {
	if k == nil {
		return "", errors.New("nil KeyEntry provided", errors.Code(-1)) // TODO
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     k.EC_X,
			Y:     k.EC_Y,
		},
		D: k.EC_D,
	}
	ecder, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err // TODO
	}
	if ecder == nil {
		return "", errors.New("no data returned when marshalling to private key", errors.Code(-1)) // TODO
	}

	block := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecder,
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&block))), nil
}
