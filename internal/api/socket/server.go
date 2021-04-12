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
	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
)

func Serve(addr string, b physical.Backend, sb vault.SecurityBarrier) error {
	if err := os.RemoveAll(addr); err != nil {
		return err
	}

	ln, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}
	log.Infof("Socket listening on %s", addr)

	u := unseal.Get()
	u.SetBackend(b)
	u.SetSecurityBarrier(sb)

	// TODO handle race here
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(ln net.Listener, c chan os.Signal) {
		sig := <-c
		log.Infof("Caught signal %s: shutting down.", sig)
		ln.Close()
		os.Exit(0)
	}(ln, sigc)

	for {
		fd, err := ln.Accept()
		if err != nil {
			log.Error("Accept error: ", err)
			return err
		}

		go serve(fd, u)
	}
}

func serve(c net.Conn, u *unseal.Unseal) {
	for {
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

		if err := u.Mount(ctx); err != nil {
			log.Debug("Mount error")
			writeError(c, u.Status(), err)

			return
		}

		utils.Memzero(data)
	}
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
