package grpc

import (
	"net"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func Serve(errCh chan error, addr string) {
	// TODO implement it
	go func() {
		log.Infof("gRPC server listening on %s", addr)
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			errCh <- err
		}
		server := grpc.NewServer()
		// TODO register servers
		errCh <- server.Serve(lis)
	}()
}
