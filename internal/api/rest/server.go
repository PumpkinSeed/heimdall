package rest

import (
	"net/http"

	"github.com/hashicorp/vault/sdk/physical"
	log "github.com/sirupsen/logrus"
)

func Serve(addr string, b physical.Backend) error {
		log.Infof("HTTP server listening on %s", addr)
		// TODO implement it, http.ListenAndServe is temporary to imitate blocking
		return http.ListenAndServe(addr, nil)
}
