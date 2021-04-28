package grpc

import (
	"context"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"net"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func Serve(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	gsrv := grpc.NewServer()
	structs.RegisterEncryptionServer(gsrv, newServer(unseal.Get()))
	log.Infof("gRPC server listening on %s", addr)

	return gsrv.Serve(lis)
}

type server struct {
	transit transit.Transit
	structs.UnimplementedEncryptionServer
}

func newServer(b *unseal.Unseal) server {
	return server{
		transit: transit.New(b),
	}
}

func (s server) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	err := s.transit.CreateKey(ctx, key.Name, key.Type.String())
	if err != nil {
		log.Errorf("Error with key creation [%s|%s]: %v", key.Name, key.Type, err)
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key:     key,
	}, nil
}

func (s server) ReadKey(ctx context.Context, key *structs.KeyName) (*structs.KeyResponse, error) {
	k, err := s.transit.GetKey(ctx, key.Name)
	if err != nil {
		log.Errorf("Error with key reading [%s]: %v", key.Name, err)
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: k.Name,
			Type: structs.EncryptionType(structs.EncryptionType_value[k.Type.String()]),
		},
	}, nil
}

func (s server) DeleteKey(ctx context.Context, key *structs.KeyName) (*structs.KeyResponse, error) {
	err := s.transit.DeleteKey(ctx, key.Name)
	if err != nil {
		log.Errorf("Error with key deletion [%s]: %v", key.Name, err)
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: key.Name,
		},
	}, nil
}

func (s server) ListKeys(ctx context.Context, _ *structs.Empty) (*structs.KeyListResponse, error) {
	keys, err := s.transit.ListKeys(ctx)
	if err != nil {
		log.Errorf("Error getting keys: %v", err)
	}

	var keySlice = make([]*structs.Key, 0, len(keys))

	for i := range keys {
		keySlice = append(keySlice, &structs.Key{
			Name: keys[i],
		})
	}

	return &structs.KeyListResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Keys:    keySlice,
	}, err
}

func (s server) Encrypt(ctx context.Context, req *structs.EncryptRequest) (*structs.CryptoResult, error) {
	e, err := s.transit.Encrypt(ctx, req.KeyName, transit.BatchRequestItem{
		Plaintext:  req.PlainText,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error encription [%s]: %v", req.KeyName, err)
	}

	return &structs.CryptoResult{
		Result: e.Ciphertext,
	}, nil
}

func (s server) Decrypt(ctx context.Context, req *structs.DecryptRequest) (*structs.CryptoResult, error) {
	d, err := s.transit.Decrypt(ctx, req.KeyName, transit.BatchRequestItem{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error decription [%s]: %v", req.KeyName, err)
	}

	return &structs.CryptoResult{
		Result: d.Plaintext,
	}, err
}

func (s server) Hash(ctx context.Context, req *structs.HashRequest) (*structs.HashResponse, error) {
	hash, err := s.transit.Hash(ctx, req.Input, req.Algorithm, req.Format)
	if err != nil {
		log.Errorf("Error hashing: %v", err)
	}

	return &structs.HashResponse{
		Result: hash,
	}, err
}

func (s server) GenerateHMAC(ctx context.Context, req *structs.HMACRequest) (*structs.HMACResponse, error) {
	hmac, err := s.transit.HMAC(ctx, req.KeyName, req.Input, req.Algorithm, int(req.KeyVersion))
	if err != nil {
		log.Errorf("Error HMAC generating: %v", err)
	}

	return &structs.HMACResponse{
		Result: hmac,
	}, err
}

func (s server) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	signature, err := s.transit.Sign(ctx, req)
	if err != nil {
		log.Errorf("Error generating sign: %v", err)
	}
	return signature, err
}

func (s server) VerifySigned(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	verificationResult, err := s.transit.VerifySign(ctx, req)
	if err != nil {
		log.Errorf("Error validating signature %v", err)
	}
	return verificationResult, err
}
