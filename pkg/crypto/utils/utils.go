package utils

import (
	"crypto/cipher"

	"github.com/PumpkinSeed/heimdall/internal/errors"
)

// Versions of the AESGCM storage methodology
const (
	AESGCMVersion1 = 0x1
	AESGCMVersion2 = 0x2
)

func Memzero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

func BarrierDecrypt(path string, gcm cipher.AEAD, cipher []byte) ([]byte, error) {
	// Capture the parts
	nonce := cipher[5 : 5+gcm.NonceSize()]
	raw := cipher[5+gcm.NonceSize():]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	// Attempt to open
	switch cipher[4] {
	case AESGCMVersion1:
		return gcm.Open(out, nonce, raw, nil)
	case AESGCMVersion2:
		aad := []byte(nil)
		if path != "" {
			aad = []byte(path)
		}
		return gcm.Open(out, nonce, raw, aad)
	default:
		return nil, errors.New("version bytes mis-match", errors.CodePkgCryptoUtilsBarrierDecrypt)
	}
}
