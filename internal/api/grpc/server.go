package grpc

import (
	"context"
	"net"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/sdk/physical"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func Serve(addr string, b physical.Backend) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	gsrv := grpc.NewServer()
	structs.RegisterEncryptionServer(gsrv, newServer(b))
	log.Infof("gRPC server listening on %s", addr)

	return gsrv.Serve(lis)
}

type server struct {
	transit transit.Transit
}

func newServer(b physical.Backend) server {
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
		Status:  getStatus(err),
		Message: getMessage(err),
		Key:     key,
	}, nil
}

func (s server) ReadKey(ctx context.Context, key *structs.KeyName) (*structs.KeyResponse, error) {
	k, err := s.transit.GetKey(ctx, key.Name)
	if err != nil {
		log.Errorf("Error with key reading [%s]: %v", key.Name, err)
	}

	return &structs.KeyResponse{
		Status:  getStatus(err),
		Message: getMessage(err),
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
		Status:  getStatus(err),
		Message: getMessage(err),
		Key: &structs.Key{
			Name: key.Name,
		},
	}, nil
}

func (s server) ListKeys(ctx context.Context, _ *structs.Empty) (*structs.KeyListResponse, error) {
	panic("implement me")
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

func getStatus(err error) structs.Status {
	if err != nil {
		return structs.Status_ERROR
	}

	return structs.Status_SUCCESS
}

func getMessage(err error) string {
	if err != nil {
		return err.Error()
	}

	return "ok"
}
