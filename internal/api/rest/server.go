package rest

import (
	"net/http"

	"github.com/hashicorp/vault/vault"
	log "github.com/sirupsen/logrus"
)

func Serve(addr string, b vault.SecurityBarrier) error {
		log.Infof("HTTP server listening on %s", addr)
		// TODO implement it, http.ListenAndServe is temporary to imitate blocking
		return http.ListenAndServe(addr, nil)
}
