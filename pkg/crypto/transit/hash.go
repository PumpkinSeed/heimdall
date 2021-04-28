package transit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"

	"github.com/hashicorp/vault/sdk/helper/keysutil"
)

func (t Transit) Hash(ctx context.Context, inputB64, algo, format string) (string, error) {
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return "", fmt.Errorf("unable to decode input as base64: %v", err)
	}

	if format == "" {
		format = "hex"
	}

	if algo == "" {
		algo = "sha2-256"
	}

	switch format {
	case "hex", "base64":
	default:
		return "", fmt.Errorf("unsupported encoding format %s; must be \"hex\" or \"base64\"", format)
	}

	var hf hash.Hash
	switch algo {
	case "sha2-256":
		hf = sha256.New()
	case "sha2-224":
		hf = sha256.New224()
	case "sha2-384":
		hf = sha512.New384()
	case "sha2-512":
		hf = sha512.New()
	default:
		return "", fmt.Errorf("unsupported algorithm %s", algo)
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
		return "", err
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
		return "", errors.New("cannot generate HMAC: version is too old (disallowed by policy)")
	}

	k, err := key.HMACKey(keyVersion)
	if err != nil {
		key.Unlock()
		return "", fmt.Errorf("HMAC creation failed: %w", err)
	}
	if key == nil {
		key.Unlock()
		return "", errors.New("HMAC key value could not be computed")
	}

	hashAlgorithm, ok := keysutil.HashTypeMap[algo]
	if !ok {
		key.Unlock()
		return "", fmt.Errorf("unsupported algorithm %q", hashAlgorithm)
	}

	hashAlg := keysutil.HashFuncMap[hashAlgorithm]

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return "", fmt.Errorf("unable to decode input as base64: %w", err)
	}

	var hf = hmac.New(hashAlg, k)
	hf.Write(input)
	retBytes := hf.Sum(nil)

	return fmt.Sprintf("vault:v%s:%s",
		strconv.Itoa(keyVersion), base64.StdEncoding.EncodeToString(retBytes),
	), nil
}
