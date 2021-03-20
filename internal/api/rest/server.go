package rest

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

func Serve(err chan error, addr string) {
	go func() {
		log.Infof("HTTP server listening on %s", addr)
		// TODO implement it, http.ListenAndServe is temporary to imitate blocking
		err <- http.ListenAndServe(addr, nil)
	}()
}
