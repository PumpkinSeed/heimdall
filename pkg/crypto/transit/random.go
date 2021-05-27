package transit

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/hashicorp/go-uuid"
)

const maxBytes = 128 * 1024

func (t Transit) GenerateRandomBytes(ctx context.Context, urlBytes, format string, bytesCount int) (string, error) {
	bytes := 0
	var err error
	if urlBytes != "" {
		bytes, err = strconv.Atoi(urlBytes)
		if err != nil {
			return "", errors.Wrap(err, "error parsing url-set byte count", errors.CodePkgCryptoTransitGenerateRandomBytesUrlBytes)
		}
	} else {
		if bytesCount == 0 {
			bytes = 32
		} else {
			bytes = bytesCount
		}
	}

	if bytes < 1 {
		return "", errors.New(`"bytes" cannot be less than 1`, errors.CodePkgCryptoTransitGenerateRandomBytesParse)
	}

	if bytes > maxBytes {
		return "", errors.Newf(errors.CodePkgCryptoTransitGenerateRandomBytesMax, `"bytes" should be less than %d`, maxBytes)
	}

	switch format {
	case "hex":
	case "base64":
	default:
		return "", errors.Newf(errors.CodePkgCryptoTransitGenerateRandomBytesFormat,
			"unsupported encoding format %q; must be \"hex\" or \"base64\"", format)
	}

	randBytes, err := uuid.GenerateRandomBytes(bytes)
	if err != nil {
		return "", errors.Wrap(err, "transit generate random bytes random generation error",
			errors.CodePkgCryptoTransitGenerateRandomBytesRandomGenerate)
	}

	var retStr string
	switch format {
	case "hex":
		retStr = hex.EncodeToString(randBytes)
	case "base64":
		retStr = base64.StdEncoding.EncodeToString(randBytes)
	}

	return retStr, nil
}
