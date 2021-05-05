package transit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
)

func (t Transit) Hash(ctx context.Context, inputB64 string, algo structs.HashType, format string) (string, error) {
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return "", errors.Wrap(err, "transit hash unable to decode input as base64", errors.CodePkgCryptoTransitHashInputFormat)
	}

	if format == "" {
		format = "hex"
	}

	if algo == structs.HashType_EmptyHashType {
		algo = structs.HashType_HashTypeSHA2256
	}

	switch format {
	case "hex", "base64":
	default:
		return "", errors.Newf(errors.CodePkgCryptoTransitHashOutputFormat, "transit hash unsupported encoding format %s; must be \"hex\" or \"base64\"", format)
	}

	var hf hash.Hash
	switch algo {
	case structs.HashType_HashTypeSHA2256:
		hf = sha256.New()
	case structs.HashType_HashTypeSHA2224:
		hf = sha256.New224()
	case structs.HashType_HashTypeSHA2384:
		hf = sha512.New384()
	case structs.HashType_HashTypeSHA2512:
		hf = sha512.New()
	default:
		return "", errors.Newf(errors.CodePkgCryptoTransitHashAlgorithmFormat, "transit hash unsupported algorithm \"%s\"", algo)
	}
	hf.Write(input)
	retBytes := hf.Sum(nil)

	var retStr string
	switch format {
	case "hex":
		retStr = hex.EncodeToString(retBytes)
	case "base64":
		retStr = base64.StdEncoding.EncodeToString(retBytes)
	}

	return retStr, nil
}

func (t Transit) HMAC(ctx context.Context, keyName, inputB64, algo string, keyVersion int, engineName string) (string, error) {
	key, err := t.GetKey(ctx, keyName, engineName)
	if err != nil {
		return "", errors.Wrap(err, "transit hmac get key error", errors.CodePkgCryptoTransitHMACGetKey)
	}

	if algo == "" {
		algo = "sha2-256"
	}

	switch {
	case keyVersion == 0:
		// Allowed, will use latest; set explicitly here to ensure the string
		// is generated properly
		keyVersion = key.LatestVersion
	case keyVersion == key.LatestVersion:
		// Allowed
	case key.MinEncryptionVersion > 0 && keyVersion < key.MinEncryptionVersion:
		key.Unlock()
		return "", errors.New("transit hmac cannot generate HMAC: version is too old (disallowed by policy)", errors.CodePkgCryptoTransitHMACKeyVersion)
	}

	k, err := key.HMACKey(keyVersion)
	if err != nil {
		key.Unlock()
		return "", errors.New("transit hmac HMAC creation failed", errors.CodePkgCryptoTransitHMAC)
	}
	if key == nil {
		key.Unlock()
		return "", errors.New("transit hmac key value could not be computed", errors.CodePkgCryptoTransitHMACCompute)
	}

	hashAlgorithm, ok := keysutil.HashTypeMap[algo]
	if !ok {
		key.Unlock()
		return "", errors.Newf(errors.CodePkgCryptoTransitHMACUnsupportedAlgo, "transit hmac unsupported algorithm %q", hashAlgorithm)
	}

	hashAlg := keysutil.HashFuncMap[hashAlgorithm]

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return "", errors.Wrap(err, "transit hmac unable to decode input as base64", errors.CodePkgCryptoTransitHMACInputFormat)
	}

	var hf = hmac.New(hashAlg, k)
	hf.Write(input)
	retBytes := hf.Sum(nil)

	return fmt.Sprintf("vault:v%s:%s",
		strconv.Itoa(keyVersion), base64.StdEncoding.EncodeToString(retBytes),
	), nil
}
