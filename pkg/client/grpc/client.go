package grpc

import (
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Options struct {
	TLS                bool
	CaFile             string
	ServerAddr         string
	ServerHostOverride string
}

func Client(addr string, o Options) (structs.EncryptionClient, error) {
	conn, err := grpc.Dial(addr, buildDialOptions(o)...)
	if err != nil {
		return nil, err
	}

	return structs.NewEncryptionClient(conn), nil
}

func buildDialOptions(o Options) []grpc.DialOption {
	var res []grpc.DialOption
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
