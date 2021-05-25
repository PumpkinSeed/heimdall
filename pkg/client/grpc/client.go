package grpc

import (
	"context"
	"sync/atomic"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	authorizationHeader = "authorization"
	engineNameHeader    = "engineName"
	defaultEnginePath   = "transit/"
)

type Options struct {
	CaFile             string
	ServerAddr         string
	ServerHostOverride string
	EngineName         string
	APIKey             string
	URLs               []string
	TLS                bool
}

func (o Options) Setup() client.Client {
	return &proxyClient{
		o:           o,
		connections: buildConnections(o),
		nxt:         0,
	}
}

func buildConnections(o Options) []grpc.ClientConnInterface {
	var res []grpc.ClientConnInterface
	for _, u := range o.URLs {
		conn, err := grpc.Dial(u, buildDialOptions(o)...)
		if err != nil {
			log.Debugf("gRPC connection error: %v", err)
			log.Error(errors.Wrap(err, "grpc dial error", errors.CodeClientGrpcDial))
			continue
		}
		res = append(res, conn)
	}

	return res
}

func buildDialOptions(o Options) []grpc.DialOption {
	res := []grpc.DialOption{
		grpc.WithUnaryInterceptor(buildInterceptor(o)),
	}
	if o.TLS {
		creds, err := credentials.NewClientTLSFromFile(o.CaFile, o.ServerHostOverride)
		if err != nil {
			log.Debugf("TLS error: %v", err)
			log.Error(errors.Wrap(err, "grpc TLS file reading error", errors.CodeClientGrpcTLSError))
		}
		res = append(res, grpc.WithTransportCredentials(creds))
	} else {
		res = append(res, grpc.WithInsecure())
	}

	res = append(res, grpc.WithBlock())

	return res
}

func buildInterceptor(o Options) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		headers := metadata.Pairs(
			authorizationHeader, o.APIKey,
			engineNameHeader, getEngineName(o),
		)
		return invoker(metadata.NewOutgoingContext(ctx, headers), method, req, reply, cc, opts...)
	}
}

func getEngineName(o Options) string {
	en := o.EngineName
	if en == "" {
		return defaultEnginePath
	}
	return en
}

type proxyClient struct {
	o           Options
	connections []grpc.ClientConnInterface
	nxt         uint32
}

func (c *proxyClient) next() structs.EncryptionClient {
	n := atomic.AddUint32(&c.nxt, 1)
	// TODO check connection state
	return structs.NewEncryptionClient(c.connections[(int(n)-1)%len(c.connections)])
}

func (c *proxyClient) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	createKey, err := c.next().CreateKey(ctx, key)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client create key error", errors.CodeClientGrpcCreateKey)
	}
	return createKey, nil
}

func (c *proxyClient) ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	key, err := c.next().ReadKey(ctx, &structs.KeyName{Name: keyName})
	if err != nil {
		return nil, errors.Wrap(err, "grpc client read key error", errors.CodeClientGrpcReadKey)
	}
	return key, nil
}

func (c *proxyClient) DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	key, err := c.next().DeleteKey(ctx, &structs.KeyName{Name: keyName})
	if err != nil {
		return nil, errors.Wrap(err, "grpc client delete key error", errors.CodeClientGrpcDeleteKey)
	}
	return key, nil
}

func (c *proxyClient) ListKeys(ctx context.Context) (*structs.KeyListResponse, error) {
	keys, err := c.next().ListKeys(ctx, &structs.Empty{})
	if err != nil {
		return nil, errors.Wrap(err, "grpc client list keys error", errors.CodeClientGrpcListKey)
	}
	return keys, nil
}

func (c *proxyClient) Encrypt(ctx context.Context, encrypt *structs.EncryptRequest) (*structs.CryptoResult, error) {
	result, err := c.next().Encrypt(ctx, encrypt)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client encrypt error", errors.CodeClientGrpcEncrypt)
	}
	return result, nil
}

func (c *proxyClient) Decrypt(ctx context.Context, decrypt *structs.DecryptRequest) (*structs.CryptoResult, error) {
	result, err := c.next().Decrypt(ctx, decrypt)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client decrypt error", errors.CodeClientGrpcDecrypt)
	}
	return result, nil
}

func (c *proxyClient) Hash(ctx context.Context, hash *structs.HashRequest) (*structs.HashResponse, error) {
	response, err := c.next().Hash(ctx, hash)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client hash error", errors.CodeClientGrpcHash)
	}
	return response, nil
}

func (c *proxyClient) GenerateHMAC(ctx context.Context, hmac *structs.HMACRequest) (*structs.HMACResponse, error) {
	generateHMAC, err := c.next().GenerateHMAC(ctx, hmac)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client hmac error", errors.CodeClientGrpcHmac)
	}
	return generateHMAC, nil
}

func (c *proxyClient) Sign(ctx context.Context, in *structs.SignParameters) (*structs.SignResponse, error) {
	sign, err := c.next().Sign(ctx, in)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client sign error", errors.CodeClientGrpcSign)
	}
	return sign, nil
}
func (c *proxyClient) VerifySigned(ctx context.Context, in *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	signed, err := c.next().VerifySigned(ctx, in)
	if err != nil {
		return nil, errors.Wrap(err, "grpc client verify sign error", errors.CodeClientGrpcVerifySign)
	}
	return signed, nil
}

func (c *proxyClient) Health(ctx context.Context, in *structs.HealthRequest) (*structs.HealthResponse, error) {
	return c.next().Health(ctx, in)
}
