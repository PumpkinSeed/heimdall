package rest

// transit/encrypt/key
// {engineName}/encrypt/{keyName} // storageban
// gochi kell
import (
	"encoding/json"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/go-chi/chi/v5"
	log "github.com/sirupsen/logrus"
)

//type EncryptionServer interface {
//	CreateKey(w http.ResponseWriter, r *http.Request)
//	ReadKey(w http.ResponseWriter, r *http.Request)
//	DeleteKey(w http.ResponseWriter, r *http.Request)
//	ListKeys(w http.ResponseWriter, r *http.Request)
//	Encrypt(w http.ResponseWriter, r *http.Request)
//	Decrypt(w http.ResponseWriter, r *http.Request)
//	Hash(w http.ResponseWriter, r *http.Request)
//	GenerateHMAC(w http.ResponseWriter, r *http.Request)
//	Sign(w http.ResponseWriter, r *http.Request)
//	VerifySigned(w http.ResponseWriter, r *http.Request)
//
//	initRoutes()
//	middleware()
//	ServeHTTP(w http.ResponseWriter, r *http.Request)
//}

func Serve(addr string) error {
	s := newServer(unseal.Get())
	s.router.Use(s.checkSecretEngineExists)
	s.initRoutes()
	log.Infof("HTTP server listening on %s", addr)
	return http.ListenAndServe(addr, s)
}

type server struct {
	router  *chi.Mux
	transit transit.Transit
}

func newServer(b *unseal.Unseal) server {
	return server{
		router:  chi.NewRouter(),
		transit: transit.New(b),
	}
}

func (s server) checkSecretEngineExists(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engineName := strings.SplitN(strings.TrimPrefix(r.RequestURI, "/"), "/", 2)[0]
		log.Printf("engine used: %s", engineName)

		next.ServeHTTP(w, r)
	})
}

func (s *server) initRoutes() {
	s.router.Post("/{engineName:^[0-9a-v]+$}/key", s.CreateKey)
}

func (s server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s server) CreateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req structs.Key
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.transit.CreateKey(ctx, req.Name, req.Type.String())
	if err != nil {
		log.Error(err)
		http.Error(w, "internal server error"+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key:     &req,
	})
}

func (s server) ReadKey(w http.ResponseWriter, r *http.Request) {
	var keyName structs.KeyName
	if err := bind(r, &keyName); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	k, err := s.transit.GetKey(r.Context(), keyName.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, &structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: k.Name,
			Type: structs.EncryptionType(structs.EncryptionType_value[k.Type.String()]),
		},
	})
}

func (s server) DeleteKey(w http.ResponseWriter, r *http.Request) {
	var key structs.Key
	if err := bind(r, &key); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := s.transit.DeleteKey(r.Context(), key.Name)
	if err != nil {
		log.Errorf("Error with key deletion [%s]: %v", key.Name, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: key.Name,
		},
	})
}

func (s server) ListKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	keys, err := s.transit.ListKeys(ctx)
	if err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var keySlice = make([]*structs.Key, 0, len(keys))

	for i := range keys {
		keySlice = append(keySlice, &structs.Key{
			Name: keys[i],
		})
	}
	successResponse(w, structs.KeyListResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Keys:    keySlice,
	})
}

func (s server) Encrypt(w http.ResponseWriter, r *http.Request) {
	var req structs.EncryptRequest
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	e, err := s.transit.Encrypt(r.Context(), req.KeyName, transit.BatchRequestItem{
		Plaintext:  req.PlainText,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error encription [%s]: %v", req.KeyName, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.CryptoResult{
		Result: e.Ciphertext,
	})
}

func (s server) Decrypt(w http.ResponseWriter, r *http.Request) {
	var req structs.DecryptRequest
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d, err := s.transit.Decrypt(r.Context(), req.KeyName, transit.BatchRequestItem{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Errorf("Error decription [%s]: %v", req.KeyName, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.CryptoResult{
		Result: d.Plaintext,
	})
}

func (s server) Hash(w http.ResponseWriter, r *http.Request) {
	var req structs.HashRequest
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := s.transit.Hash(r.Context(), req.Input, req.Algorithm, req.Format)
	if err != nil {
		log.Errorf("Error hashing: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.HashResponse{
		Result: hash,
	})
}

func (s server) GenerateHMAC(w http.ResponseWriter, r *http.Request) {
	var req structs.HMACRequest
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hmac, err := s.transit.HMAC(r.Context(), req.KeyName, req.Input, req.Algorithm, int(req.KeyVersion))
	if err != nil {
		log.Errorf("Error HMAC generating: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.HMACResponse{
		Result: hmac,
	})
}

func (s server) Sign(w http.ResponseWriter, r *http.Request) {
	var req structs.SignParameters
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signature, err := s.transit.Sign(r.Context(), &req)
	if err != nil {
		log.Errorf("Error generating sign: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, signature)
}

func (s server) VerifySigned(w http.ResponseWriter, r *http.Request) {
	var req structs.VerificationRequest
	if err := bind(r, &req); err != nil {
		log.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	verificationResult, err := s.transit.VerifySign(r.Context(), &req)
	if err != nil {
		log.Errorf("Error validating signature %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, verificationResult)
}

func bind(r *http.Request, v interface{}) error {
	rawBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if err := json.Unmarshal(rawBody, v); err != nil {
		return err
	}

	return err
}

func successResponse(w http.ResponseWriter, v interface{}) {
	result, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal server error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(result); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
