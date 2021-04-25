package flags

import "github.com/urfave/cli/v2"

const (
	NameVerbose       = "verbose"
	NameGrpc          = "grpc"
	NameRest          = "rest"
	NameSocket        = "socket"
	NameThreshold     = "threshold"
	NameTotalShares   = "total-shares"
	NameConsulAddress = "consul-address"
	NameConsulToken   = "consul-token"
	NameInMemory      = "in-memory"

	grpcDefaultAddr   = "0.0.0.0:9090"
	restDefaultAddr   = "0.0.0.0:8080"
	socketDefaultPath = "/tmp/heimdall.sock"
	thresholdDefault  = 3
	totalSharesDefault = 5
)

var (
	Verbose = &cli.BoolFlag{
		Name: NameVerbose,
	}

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

	Threshold = &cli.IntFlag{
		Name:  NameThreshold,
		Usage: "The shamir's threshold",
		Value: thresholdDefault,
	}

	TotalShares = &cli.IntFlag{
		Name: NameTotalShares,
		Usage: "The shamir's total shares",
		Value: totalSharesDefault,
	}

	// TODO add flag to handle multiple database types
	ConsulAddress = &cli.StringFlag{
		Name:  NameConsulAddress,
		Usage: "Add consul's connection string here",
	}
	ConsulToken = &cli.StringFlag{
		Name:  NameConsulToken,
		Usage: "Add consul's access token here",
	}
	InMemory = &cli.BoolFlag{
		Name:  NameInMemory,
		Usage: "Starts the server with in memory physical backend for development",
		Value: false,
	}
)
