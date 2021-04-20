package socket

import (
	"context"
	"encoding/json"
	"net"
	"os"

	"github.com/PumpkinSeed/heimdall/internal/api/socket/services"
	"github.com/PumpkinSeed/heimdall/internal/structs"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	log "github.com/sirupsen/logrus"
)

var servers = map[structs.SocketType]Server{}

type Server interface {
	Handler(ctx context.Context, req structs.SocketRequest) (structs.SocketResponse, error)
}

func initServers(u *unseal.Unseal) {
	servers[structs.SocketUnseal] = services.NewUnseal(u)
}

func Serve(addr string) error {
	if err := os.RemoveAll(addr); err != nil {
		return err
	}

	ln, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}
	log.Infof("Socket listening on %s", addr)

	initServers(unseal.Get())

	for {
		fd, err := ln.Accept()
		if err != nil {
			log.Error("Accept error: ", err)

			return err
		}

		serve(fd)
	}
}

func serve(c net.Conn) {
	req, err := bindInput(c)
	if err != nil {
		log.Errorf("error at input binding: %v", err)
		writeError(c, err)

		return
	}

	res, err := servers[req.Type].Handler(context.Background(), req)
	if err != nil {
		log.Errorf("error request handling: %v", err)
		writeError(c, err)
		write(c, res.Data)

		return
	}

	write(c, res.Data)
}

func bindInput(c net.Conn) (structs.SocketRequest, error) {
	buf := make([]byte, 512)
	nr, err := c.Read(buf)
	if err != nil {
		return structs.SocketRequest{}, err
	}

	var req structs.SocketRequest
	if err := json.Unmarshal(buf[0:nr], &req); err != nil {
		return structs.SocketRequest{}, err
	}
	if req.Type == structs.SocketUnknown {
		return structs.SocketRequest{}, structs.ErrUnknownRequest
	}

	return req, nil
}

func writeError(c net.Conn, err error) {
	writeStr(c, "\nError:\n")
	writeStr(c, err.Error())
}

func writeStr(c net.Conn, s string) {
	write(c, []byte(s))
}

func write(c net.Conn, v []byte) {
	if _, err := c.Write(v); err != nil {
		log.Error(err)
	}
}
