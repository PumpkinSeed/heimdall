package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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
		return nil, errors.Newf(errors.CodePkgCryptoTransitExportType, "invalid export type: [%s]", exportType)
	}

	p, err := t.GetKey(ctx, keyName, engineName)
	if err != nil {
		return nil, errors.Wrap(err, "transit export get key error", errors.CodePkgCryptoTransitExportGetKey)
	}

	if !p.Exportable {
		return nil, errors.New("key is not exportable", errors.CodePkgCryptoTransitExportNonExportable)
	}

	switch exportType {
	case ExportTypeEncryptionKey:
		if !p.Type.EncryptionSupported() {
			return nil, errors.New("encryption not supported for the key", errors.CodePkgCryptoTransitExportTypeEncryptKeyNotSupported)
		}
	case ExportTypeSigningKey:
		if !p.Type.SigningSupported() {
			return nil, errors.New("signing not supported for the key", errors.CodePkgCryptoTransitExportTypeSigningKeyNotSupported)
		}
	}

	retKeys := map[string]string{}
	switch version {
	case "":
		for k, v := range p.Keys {
			exportKey, err := getExportKey(p, &v, exportType)
			if err != nil {
				return nil, errors.Wrap(err, "get export key error", errors.CodePkgCryptoTransitExportGetExportKey)
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
				return nil, errors.Newf(errors.CodePkgCryptoTransitExportInvalidVersionFormat, "invalid key version [%s]", version)
			}
		}

		if versionValue < p.MinDecryptionVersion {
			return nil, errors.New("version for export is below minimum decryption version", errors.CodePkgCryptoTransitExportInvalidVersionLessThanMin)
		}
		key, ok := p.Keys[strconv.Itoa(versionValue)]
		if !ok {
			return nil, errors.New("version does not exist or cannot be found", errors.CodePkgCryptoTransitExportVersionNotFound)
		}

		exportKey, err := getExportKey(p, &key, exportType)
		if err != nil {
			return nil, errors.Wrap(err, "get export key error for specified version", errors.CodePkgCryptoTransitExportGetExportKey)
		}

		retKeys[strconv.Itoa(versionValue)] = exportKey
	}

	return retKeys, nil
}

func getExportKey(policy *keysutil.Policy, key *keysutil.KeyEntry, exportType string) (string, error) {
	if policy == nil {
		return "", errors.New("nil policy provided", errors.CodePkgCryptoTransitExportGetExportKeyPolicyMissing)
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
				return "", errors.Wrap(err, "key entry to EC private key error", errors.CodePkgCryptoTransitExportGetExportKeyToPrivateKey)
			}
			return ecKey, nil

		case keysutil.KeyType_ED25519:
			return strings.TrimSpace(base64.StdEncoding.EncodeToString(key.Key)), nil

		case keysutil.KeyType_RSA2048, keysutil.KeyType_RSA3072, keysutil.KeyType_RSA4096:
			return encodeRSAPrivateKey(key.RSAKey), nil
		}
	}

	return "", errors.Newf(errors.CodePkgCryptoTransitExportGetExportKeyUnknownType, "unknown key type [%v]", policy.Type)
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
		return "", errors.New("nil KeyEntry provided", errors.CodePkgCryptoTransitExportGetExportKeyToPrivateKeyMissingEntry)
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
		return "", errors.Wrap(err, "keyEntryToECPrivateKey x509 Marshal EC error", errors.CodePkgCryptoTransitExportGetExportKeyToPrivateKeyMarshal)
	}
	if ecder == nil {
		return "", errors.New("no data returned when marshalling to private key", errors.CodePkgCryptoTransitExportGetExportKeyToPrivateKeyMarshalResult)
	}

	block := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: ecder,
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&block))), nil
}
