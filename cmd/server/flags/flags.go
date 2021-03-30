package flags

import "github.com/urfave/cli/v2"

const (
	NameGrpc   = "grpc"
	NameRest   = "rest"
	NameSocket = "socket"

	grpcDefaultAddr   = "0.0.0.0:9090"
	restDefaultAddr   = "0.0.0.0:8080"
	socketDefaultPath = "/tmp/heimdall.sock"
)

var (
	Grpc = &cli.StringFlag{
		Name:  NameGrpc,
		Usage: "Starts grpc server and listen on specified address",
		Value: grpcDefaultAddr,
	}

	Rest = &cli.StringFlag{
		Name:  NameRest,
		Usage: "Starts HTTP server and listen on specified address",
		Value: restDefaultAddr,
	}
	Socket = &cli.StringFlag{
		Name:  NameSocket,
		Usage: "Using the specified socket",
		Value: socketDefaultPath,
	}
)
