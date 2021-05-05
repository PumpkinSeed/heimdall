package grpc

import (
	"context"
	"net"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/PumpkinSeed/heimdall/pkg/healthcheck"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/PumpkinSeed/heimdall/pkg/token"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func Serve(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.Wrap(err, "grpc serve error", errors.CodeApiGrpc)
	}
	s := newServer(unseal.Get())
	gsrv := grpc.NewServer(grpc.StreamInterceptor(
		grpc_logrus.StreamServerInterceptor(log.NewEntry(log.New())),
	), grpc.UnaryInterceptor(s.AuthInterceptor()))
	structs.RegisterEncryptionServer(gsrv, s)
	log.Infof("gRPC server listening on %s", addr)

	if err := gsrv.Serve(lis); err != nil {
		return errors.Wrap(err, "grpc serve error", errors.CodeApiGrpc)
	}

	return nil
}

type server struct {
	transit transit.Transit
	health  healthcheck.Healthcheck
	ts      *token.TokenStore
	structs.UnimplementedEncryptionServer
}

func newServer(u *unseal.Unseal) server {
	return server{
		transit: transit.New(u),
		health:  healthcheck.New(u),
		ts:      token.NewTokenStore(u),
	}
}

func (s server) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	err := s.transit.CreateKey(ctx, key.Name, key.Type.String(), key.EngineName)
	if err != nil {
		log.Errorf("Error with key creation [%s|%s]: %v", key.Name, key.Type, err)
		return nil, errors.Wrap(err, "grpc create key error", errors.CodeApiGrpcCreateKey)
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key:     key,
	}, nil
}

func (s server) ReadKey(ctx context.Context, key *structs.KeyName) (*structs.KeyResponse, error) {
	k, err := s.transit.GetKey(ctx, key.Name, key.EngineName)
	if err != nil {
		log.Errorf("Error with key reading [%s]: %v", key.Name, err)
		return nil, errors.Wrap(err, "grpc read key error", errors.CodeApiGrpcReadKey)
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
	err := s.transit.DeleteKey(ctx, key.Name, key.EngineName)
	if err != nil {
		log.Errorf("Error with key deletion [%s]: %v", key.Name, err)
		return nil, errors.Wrap(err, "grpc delete key error", errors.CodeApiGrpcDeleteKey)
	}

	return &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: key.Name,
		},
	}, nil
}

func (s server) ListKeys(ctx context.Context, in *structs.Empty) (*structs.KeyListResponse, error) {
	keys, err := s.transit.ListKeys(ctx, in.EngineName)
	if err != nil {
		log.Errorf("Error getting keys: %v", err)
		return nil, errors.Wrap(err, "grpc list key error", errors.CodeApiGrpcListKey)
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
	}, nil
}

func (s server) Encrypt(ctx context.Context, req *structs.EncryptRequest) (*structs.CryptoResult, error) {
	e, err := s.transit.Encrypt(ctx, req.KeyName, req.EngineName, transit.BatchRequestItem{
		Plaintext:  req.PlainText,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error encription [%s]: %v", req.KeyName, err)
		return nil, errors.Wrap(err, "grpc encrypt error", errors.CodeApiGrpcEncrypt)
	}

	return &structs.CryptoResult{
		Result: e.Ciphertext,
	}, nil
}

func (s server) Decrypt(ctx context.Context, req *structs.DecryptRequest) (*structs.CryptoResult, error) {
	d, err := s.transit.Decrypt(ctx, req.KeyName, req.EngineName, transit.BatchRequestItem{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error decription [%s]: %v", req.KeyName, err)
		return nil, errors.Wrap(err, "grpc decrypt error", errors.CodeApiGrpcDecrypt)
	}

	return &structs.CryptoResult{
		Result: d.Plaintext,
	}, nil
}

func (s server) Hash(ctx context.Context, req *structs.HashRequest) (*structs.HashResponse, error) {
	hash, err := s.transit.Hash(ctx, req.Input, req.Algorithm, req.Format)
	if err != nil {
		log.Errorf("Error hashing: %v", err)
		return nil, errors.Wrap(err, "grpc hash error", errors.CodeApiGrpcHash)
	}

	return &structs.HashResponse{
		Result: hash,
	}, nil
}

func (s server) GenerateHMAC(ctx context.Context, req *structs.HMACRequest) (*structs.HMACResponse, error) {
	hmac, err := s.transit.HMAC(ctx, req.KeyName, req.Input, req.Algorithm, int(req.KeyVersion), req.EngineName)
	if err != nil {
		log.Errorf("Error HMAC generating: %v", err)
		return nil, errors.Wrap(err, "grpc HMAC error", errors.CodeApiGrpcHMAC)
	}

	return &structs.HMACResponse{
		Result: hmac,
	}, nil
}

func (s server) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	signature, err := s.transit.Sign(ctx, req)
	if err != nil {
		log.Errorf("Error generating sign: %v", err)
		return nil, errors.Wrap(err, "grpc sign error", errors.CodeApiGrpcSign)
	}
	return signature, nil
}

func (s server) VerifySigned(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	verificationResult, err := s.transit.VerifySign(ctx, req)
	if err != nil {
		log.Errorf("Error validating signature %v", err)
		return nil, errors.Wrap(err, "grpc verify sign error", errors.CodeApiGrpcVerifySign)
	}
	return verificationResult, nil
}

func (s server) Health(ctx context.Context, req *structs.HealthRequest) (*structs.HealthResponse, error) {
	return s.health.Check(ctx), nil
}

func (s server) AuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "Retrieving metadata is failed")
		}
		apiKey := md.Get("authorization")
		if len(apiKey) == 0 {
			return nil, status.Errorf(codes.Unauthenticated, "Authorization token is not supplied")
		}
		validToken, err := s.ts.CheckToken(ctx, apiKey[0])
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if !validToken {
			return nil, status.Error(codes.Unauthenticated, "invalid api key")
		}

		return handler(ctx, req)
	}
}
