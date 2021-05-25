package transit

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/emvi/null"
)

type GenerateRequest struct {
	Name       string      `json:"name"`
	Plaintext  string      `json:"plaintext"`
	Context    null.String `json:"context"`
	Nonce      null.String `json:"nonce"`
	Bits       null.Int64  `json:"bits"`
	KeyVersion null.Int64  `json:"key_version"`
}

type GenerateResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
	Plaintext  string `json:"plaintext"`
}

func (t Transit) GenerateKey(ctx context.Context, engineName string, req GenerateRequest) (GenerateResponse, error) {
	plaintextAllowed := false
	switch req.Plaintext {
	case "plaintext":
		plaintextAllowed = true
	case "wrapped":
	default:
		return GenerateResponse{}, errors.New("Invalid path, must be 'plaintext' or 'wrapped'", errors.Code(-1)) // TODO
	}

	var err error

	// Decode the context if any
	var decodedContext []byte
	if req.Context.Valid && len(req.Context.String) != 0 {
		decodedContext, err = base64.StdEncoding.DecodeString(req.Context.String)
		if err != nil {
			return GenerateResponse{}, errors.Wrap(err, "failed to base64-decode context", errors.Code(-1)) // TODO
		}
	}

	// Decode the nonce if any
	var decodedNonce []byte
	if req.Nonce.Valid && len(req.Nonce.String) != 0 {
		decodedNonce, err = base64.StdEncoding.DecodeString(req.Nonce.String)
		if err != nil {
			return GenerateResponse{}, errors.Wrap(err, "failed to base64-decode nonce", errors.Code(-1)) // TODO
		}
	}

	p, err := t.GetKey(ctx, req.Name, engineName)
	if err != nil {
		return GenerateResponse{}, errors.Wrap(err, "encryption key not found", errors.Code(-1)) // TODO
	}

	if !req.Bits.Valid {
		req.Bits.SetValid(256)
	}
	newKey := make([]byte, 32)
	switch req.Bits.Int64 {
	case 512:
		newKey = make([]byte, 64)
	case 256:
	case 128:
		newKey = make([]byte, 16)
	default:
		return GenerateResponse{}, errors.New("invalid bit length", errors.Code(-1)) // TODO
	}
	_, err = rand.Read(newKey)
	if err != nil {
		return GenerateResponse{}, err // TODO
	}

	ciphertext, err := p.Encrypt(int(req.KeyVersion.Int64), decodedContext, decodedNonce, base64.StdEncoding.EncodeToString(newKey))
	if err != nil {
		return GenerateResponse{}, errors.Wrap(err, "", errors.Code(-1)) // TODO
	}

	if ciphertext == "" {
		return GenerateResponse{}, errors.New("empty ciphertext returned", errors.Code(-1)) // TODO
	}

	keyVersion := int(req.KeyVersion.Int64)
	if keyVersion == 0 {
		keyVersion = p.LatestVersion
	}

	resp := GenerateResponse{
		Ciphertext: ciphertext,
		KeyVersion: keyVersion,
	}

	if plaintextAllowed {
		resp.Plaintext = base64.StdEncoding.EncodeToString(newKey)
	}

	return resp, nil
}
