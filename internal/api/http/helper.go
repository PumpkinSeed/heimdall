package http

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	log "github.com/sirupsen/logrus"
)

func bind(r *http.Request, v interface{}) error {
	rawBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.Wrap(err, "http bind body read error", errors.CodeApiHTTPBindRead)
	}
	defer r.Body.Close()

	if err := json.Unmarshal(rawBody, v); err != nil {
		return errors.Wrap(err, "http bind unmarshal error", errors.CodeApiHTTPBindUnmarshal)
	}

	return err
}

func successResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Add("Content-type", "application/json")
	result, err := json.Marshal(v)
	if err != nil {
		log.Error(errors.Wrap(err, "http success response marshal error", errors.CodeApiHTTPSuccessResponseMarshal))
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(result); err != nil {
		log.Error(errors.Wrap(err, "http success response write error", errors.CodeApiHTTPSuccessResponseWrite))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
