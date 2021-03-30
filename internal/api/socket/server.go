package socket

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/hashicorp/vault/sdk/physical"
	log "github.com/sirupsen/logrus"
)

func Serve(addr string, b physical.Backend) error {
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}
	log.Infof("Socket listening on %s", addr)

	// TODO handle race here
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(ln net.Listener, c chan os.Signal) {
		sig := <-c
		log.Printf("Caught signal %s: shutting down.", sig)
		ln.Close()
		os.Exit(0)
	}(ln, sigc)

	for {
		fd, err := ln.Accept()
		if err != nil {
			log.Fatal("Accept error: ", err)
		}

		go serve(fd)
	}
}

func serve(c net.Conn) {
	for {
		data, err := bindInput(c)
		if err != nil {
			writeStr(c, "invalid input")

			return
		}
		u := unseal.Get()
		ctx := context.Background()
		done, err := u.Unseal(ctx, nil, string(data))
		if err != nil {
			writeError(c, u.Status(), err)

			return
		}
		if !done {
			writeStr(c, u.Status().String())

			return
		}

		if err := u.Keyring(ctx, nil); err != nil {
			writeError(c, u.Status(), err)

			return
		}

		if err := u.Mount(ctx, nil); err != nil {
			writeError(c, u.Status(), err)

			return
		}
	}
}

func bindInput(c net.Conn) ([]byte, error) {
	buf := make([]byte, 512)
	nr, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	defer utils.Memzero(buf)

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
		log.Fatal(err)
	}
}
