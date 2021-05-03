package grpc

import (
	"context"
	"sync/atomic"

	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Options struct {
	CaFile             string
	ServerAddr         string
	ServerHostOverride string
	EngineName         string
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
			log.Errorf("gRPC connection error: %v", err)
			continue
		}
		res = append(res, conn)
	}

	return res
}

func buildDialOptions(o Options) []grpc.DialOption {
	res := []grpc.DialOption{}
	if o.TLS {
		creds, err := credentials.NewClientTLSFromFile(o.CaFile, o.ServerHostOverride)
		if err != nil {
			log.Error(err)
		}
		res = append(res, grpc.WithTransportCredentials(creds))
	} else {
		res = append(res, grpc.WithInsecure())
	}

	res = append(res, grpc.WithBlock())

	return res
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
	key.EngineName = c.o.EngineName
	return c.next().CreateKey(ctx, key)
}

func (c *proxyClient) ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	return c.next().ReadKey(ctx, &structs.KeyName{Name: keyName, EngineName: c.o.EngineName})
}

func (c *proxyClient) DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	return c.next().DeleteKey(ctx, &structs.KeyName{Name: keyName, EngineName: c.o.EngineName})
}

func (c *proxyClient) ListKeys(ctx context.Context) (*structs.KeyListResponse, error) {
	return c.next().ListKeys(ctx, &structs.Empty{EngineName: c.o.EngineName})
}

func (c *proxyClient) Encrypt(ctx context.Context, encrypt *structs.EncryptRequest) (*structs.CryptoResult, error) {
	encrypt.EngineName = c.o.EngineName
	return c.next().Encrypt(ctx, encrypt)
}

func (c *proxyClient) Decrypt(ctx context.Context, decrypt *structs.DecryptRequest) (*structs.CryptoResult, error) {
	decrypt.EngineName = c.o.EngineName
	return c.next().Decrypt(ctx, decrypt)
}

func (c *proxyClient) Hash(ctx context.Context, hash *structs.HashRequest) (*structs.HashResponse, error) {
	hash.EngineName = c.o.EngineName
	return c.next().Hash(ctx, hash)
}

func (c *proxyClient) GenerateHMAC(ctx context.Context, hmac *structs.HMACRequest) (*structs.HMACResponse, error) {
	hmac.EngineName = c.o.EngineName
	return c.next().GenerateHMAC(ctx, hmac)
}

func (c *proxyClient) Sign(ctx context.Context, in *structs.SignParameters) (*structs.SignResponse, error) {
	in.EngineName = c.o.EngineName
	return c.next().Sign(ctx, in)
}
func (c *proxyClient) VerifySigned(ctx context.Context, in *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	in.EngineName = c.o.EngineName
	return c.next().VerifySigned(ctx, in)
}

func (c *proxyClient) Health(ctx context.Context, in *structs.HealthRequest) (*structs.HealthResponse, error) {
	return c.next().Health(ctx, in)
}
