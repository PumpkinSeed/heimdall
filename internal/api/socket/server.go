package socket

import (
	"context"
	"net"
	"os"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	log "github.com/sirupsen/logrus"
)

func Serve(addr string) error {
	if err := os.RemoveAll(addr); err != nil {
		return err
	}

	ln, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}
	log.Infof("Socket listening on %s", addr)

	for {
		fd, err := ln.Accept()
		if err != nil {
			log.Error("Accept error: ", err)
			return err
		}

		serve(fd, unseal.Get())
	}
}

func serve(c net.Conn, u *unseal.Unseal) {
	if u.Status().Unsealed {
		writeStr(c, u.Status().String())

		return
	}
	data, err := bindInput(c)
	if err != nil {
		writeStr(c, "invalid input")

		return
	}
	ctx := context.Background()
	done, err := u.Unseal(ctx, string(data))
	if err != nil {
		writeError(c, u.Status(), err)

		return
	}
	if !done {
		log.Debug("Unseal not done yet")
		writeStr(c, u.Status().String())

		return
	}
	if err := u.Keyring(ctx); err != nil {
		log.Debug("Keyring init error")
		writeError(c, u.Status(), err)

		return
	}
	barrierPath, err := u.Mount(ctx)
	if err != nil {
		log.Debug("Mount error")
		writeError(c, u.Status(), err)

		return
	}
	if err := u.PostProcess(ctx, barrierPath); err != nil {
		log.Debug("Post process error")
		writeError(c, u.Status(), err)

		return
	}
	utils.Memzero(data)
	writeStr(c, u.Status().String())
}

func bindInput(c net.Conn) ([]byte, error) {
	buf := make([]byte, 44)
	nr, err := c.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[0:nr], nil
}

func writeError(c net.Conn, s unseal.Status, err error) {
	writeStr(c, "Error:\n")
	writeStr(c, s.String())
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
