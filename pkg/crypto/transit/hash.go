package transit

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
)

func (t Transit) Hash(ctx context.Context, inputB64, algo, format string) (string, error) {
	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return "", fmt.Errorf("unable to decode input as base64: %s", err)
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
