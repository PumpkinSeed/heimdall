package socket

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const Path = "/tmp/heimdall.sock"

func Serve(addr string) error {
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return err
	}
	log.Infof("Socket listening on %s", addr)
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
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		// TODO do the unsealing here
		log.Debugf("Server got: %s", string(data))
		_, err = c.Write(data)
		if err != nil {
			log.Fatal("Writing client error: ", err)
		}
	}
}
