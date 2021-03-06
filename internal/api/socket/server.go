package socket

import (
	"context"
	"encoding/json"
	"net"
	"os"

	"github.com/PumpkinSeed/heimdall/internal/api/socket/services"
	"github.com/PumpkinSeed/heimdall/internal/errors"
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
	servers[structs.SocketInit] = services.NewInit(u)
	servers[structs.TokenCreate] = services.NewTokenCreate(u)
}

func Serve(addr string) error {
	if err := os.RemoveAll(addr); err != nil {
		return errors.Wrap(err, "socket remove error", errors.CodeApiSocket)
	}

	ln, err := net.Listen("unix", addr)
	if err != nil {
		return errors.Wrap(err, "socket listen error", errors.CodeApiSocket)
	}
	log.Infof("Socket listening on %s", addr)

	initServers(unseal.Get())

	for {
		fd, err := ln.Accept()
		if err != nil {
			log.Debugf("Accept error: %v", err)

			return errors.Wrap(err, "socket listener accept error", errors.CodeApiSocket)
		}

		serve(fd)
	}
}

func serve(c net.Conn) {
	req, err := bindInput(c)
	if err != nil {
		log.Debugf("error at input binding: %v", err)
		log.Error(errors.Wrap(err, "socket bind error", errors.CodeApiSocketBind))
		writeError(c, err)

		return
	}

	res, err := servers[req.Type].Handler(context.Background(), req)
	if err != nil {
		log.Debugf("error request handling: %v", err)
		log.Error(errors.Wrap(err, "socket request handler error", errors.CodeApiSocketHandler))
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
		return structs.SocketRequest{}, errors.Wrap(err, "socket read error", errors.CodeApiSocketBindRead)
	}

	var req structs.SocketRequest
	if err := json.Unmarshal(buf[0:nr], &req); err != nil {
		return structs.SocketRequest{}, errors.Wrap(err, "socket unmarshal error", errors.CodeApiSocketBindUnmarshal)
	}
	if req.Type == structs.SocketUnknown {
		return structs.SocketRequest{}, errors.Wrap(structs.ErrUnknownRequest, "socket unknown response type error", errors.CodeApiSocketBindUnknown)
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
		log.Error(errors.NewErr(err, errors.CodeApiSocketWrite))
	}
}
