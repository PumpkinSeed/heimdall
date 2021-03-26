package grpc

import (
	"context"
	"net"

	"github.com/PumpkinSeed/heimdall/pkg/crypto"
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
	structs.RegisterEncryptionServer(gsrv, server{})
	log.Infof("gRPC server listening on %s", addr)
	return gsrv.Serve(lis)
}

type server struct {
	cry crypto.Crypto
}

func (s server) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	panic("implement me")
}

func (s server) ReadKey(ctx context.Context, name *structs.KeyName) (*structs.KeyResponse, error) {
	panic("implement me")
}

func (s server) DeleteKey(ctx context.Context, name *structs.KeyName) (*structs.KeyResponse, error) {
	panic("implement me")
}

func (s server) ListKeys(ctx context.Context, _ *structs.Empty) (*structs.KeyListResponse, error) {
	panic("implement me")
}

func (s server) Encrypt(ctx context.Context, request *structs.EncryptRequest) (*structs.CryptoResult, error) {
	panic("implement me")
}

func (s server) Decrypt(ctx context.Context, request *structs.DecryptRequest) (*structs.CryptoResult, error) {
	panic("implement me")
}

func (s server) Unseal(ctx context.Context, request *structs.UnsealRequest) (*structs.UnsealResponse, error) {
	unseal, err := s.cry.Unseal(ctx, request.Key)
	if err != nil {
		log.Debugf("unsealing key: %s", request.Key)
		log.Errorf("error unsealing: %v", err)
		return nil, err
	}

	return &unseal, nil
}
