package rest

import (
	"net/http"

	log "github.com/sirupsen/logrus"
)

func Serve(addr string) error {
	log.Infof("HTTP server listening on %s", addr)
	// TODO implement it, http.ListenAndServe is temporary to imitate blocking
	return http.ListenAndServe(addr, nil)
}
