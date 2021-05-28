package http

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/transit"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/unseal"
	"github.com/PumpkinSeed/heimdall/pkg/crypto/utils"
	"github.com/PumpkinSeed/heimdall/pkg/healthcheck"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/PumpkinSeed/heimdall/pkg/token"
	"github.com/emvi/null"
	"github.com/go-chi/chi/v5"
	log "github.com/sirupsen/logrus"
)

const ctxKeyEngine = "engine"

func Serve(addr string) error {
	s := newServer(unseal.Get())
	s.Init()
	log.Infof("HTTP server listening on %s", addr)
	err := http.ListenAndServe(addr, s)
	if err != nil {
		return errors.Wrap(err, "http listen error", errors.CodeApiHTTP)
	}
	return nil
}

type server struct {
	*chi.Mux
	transit transit.Transit
	health  healthcheck.Healthcheck
	ts      *token.TokenStore
}

func newServer(u *unseal.Unseal) EncryptionServer {
	return &server{
		Mux:     chi.NewRouter(),
		transit: transit.New(u),
		health:  healthcheck.New(u),
		ts:      token.NewTokenStore(u),
	}
}

func (s server) checkSecretEngineExists(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := utils.EngineNameRegexp.FindStringSubmatch(r.RequestURI)
		if len(m) == 0 || len(m[0]) == 0 {
			log.Error("missing engine name")
			http.Error(w, "missing engine name", http.StatusBadRequest)
			return
		}
		engineName := strings.TrimPrefix(m[0], "/")
		if exists, err := s.transit.CheckEngine(engineName); err != nil {
			log.Errorf("engine check error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else if !exists {
			log.Errorf("engine not found: %s", engineName)
			http.Error(w, "engine not found", http.StatusBadRequest)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyEngine, engineName))

		next.ServeHTTP(w, r)
	})
}

func (s *server) checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := r.Header.Get("authorization")
		found, err := s.ts.CheckToken(r.Context(), t)
		if err != nil {
			log.Debugf("%v", err)
			http.Error(w, "please provide valid token", http.StatusBadRequest)
			return
		}
		if !found {
			log.Debugf("token not found %s", t)
			http.Error(w, "please provide valid token", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) Init() {
	s.Get("/health", s.Health)
	s.Route("/{engineName:^[0-9a-v]+$}", func(r chi.Router) {
		r.Use(s.checkSecretEngineExists)
		r.Use(s.checkToken)
		r.Post("/key", s.CreateKey)
		r.Get("/key", s.ListKeys)
		r.Get("/key/{key}", s.ReadKey)
		r.Delete("/key/{key}", s.DeleteKey)
		r.Post("/keys/{key}/config", s.UpdateKeyConfiguration)
		r.Post("/keys/{key}/rotate", s.RotateKey)

		r.Post("/encrypt", s.Encrypt)
		r.Post("/decrypt", s.Decrypt)
		r.Post("/hash", s.Hash)
		r.Post("/hmac", s.GenerateHMAC)
		r.Post("/sign", s.Sign)
		r.Post("/verify", s.VerifySigned)

		r.Post("/rewrap/{key}", s.Rewrap)
		r.Get("/export/{keyType}/{keyName}/{version}", s.ExportKey)
		r.Get("/backup/{keyName}", s.BackupKey)
		r.Post("/restore/{keyName}", s.RestoreKey)
		r.Post("/datakey/{keyType}/{keyName}", s.GenerateKey)
		r.Post("/random/{bytesCount:[0-9]+}", s.GenerateRandomBytes)
	})
}

func (s server) CreateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req structs.Key
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http create key bind error", errors.CodeApiHTTPCreateKey))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPCreateKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	err := s.transit.CreateKey(ctx, req.Name, req.Type.String(), engineName)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call create key error", errors.CodeApiHTTPCreateKey))
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
	key := chi.URLParam(r, "key")
	if key == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPReadKey))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPReadKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	k, err := s.transit.GetKey(r.Context(), key, engineName)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call get key error", errors.CodeApiHTTPReadKey))
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
	key := chi.URLParam(r, "key")
	if key == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPDeleteKey))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}

	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPDeleteKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	err := s.transit.DeleteKey(r.Context(), key, engineName)
	if err != nil {
		log.Debugf("Error with key deletion [%s]: %v", key, err)
		log.Error(errors.Wrap(err, "http transit call delete key error", errors.CodeApiHTTPDeleteKey))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, structs.KeyResponse{
		Status:  utils.GetStatus(err),
		Message: utils.GetMessage(err),
		Key: &structs.Key{
			Name: key,
		},
	})
}

func (s server) ListKeys(w http.ResponseWriter, r *http.Request) {
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPListKeysEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	keys, err := s.transit.ListKeys(r.Context(), engineName)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call list keys error", errors.CodeApiHTTPListKeys))
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
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPEncryptEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	var req structs.EncryptRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http encrypt bind error", errors.CodeApiHTTPEncrypt))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	e, err := s.transit.Encrypt(r.Context(), req.KeyName, engineName, transit.BatchRequestItem{
		Plaintext:  req.PlainText,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Debugf("Error encription [%s]: %v", req.KeyName, err)
		log.Error(errors.Wrap(err, "http transit call encrypt error", errors.CodeApiHTTPEncrypt))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.CryptoResult{
		Result: e.Ciphertext,
	})
}

func (s server) Decrypt(w http.ResponseWriter, r *http.Request) {
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPDecryptEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	var req structs.DecryptRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http decrypt bind error", errors.CodeApiHTTPDecrypt))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d, err := s.transit.Decrypt(r.Context(), req.KeyName, engineName, transit.BatchRequestItem{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Debugf("Error decription [%s]: %v", req.KeyName, err)
		log.Error(errors.Wrap(err, "http transit call encrypt error", errors.CodeApiHTTPDecrypt))
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
		log.Error(errors.Wrap(err, "http hash bind error", errors.CodeApiHTTPHash))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := s.transit.Hash(r.Context(), req.Input, req.Algorithm, req.Format)
	if err != nil {
		log.Debugf("Error hashing: %v", err)
		log.Error(errors.Wrap(err, "http transit call hash error", errors.CodeApiHTTPHash))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.HashResponse{
		Result: hash,
	})
}

func (s server) GenerateHMAC(w http.ResponseWriter, r *http.Request) {
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPHmacEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	var req structs.HMACRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http hmac bind error", errors.CodeApiHTTPHash))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hmac, err := s.transit.HMAC(r.Context(), req.KeyName, req.Input, req.Algorithm, int(req.KeyVersion), engineName)
	if err != nil {
		log.Debugf("Error HMAC generating: %v", err)
		log.Error(errors.Wrap(err, "http transit call hmac error", errors.CodeApiHTTPHmac))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.HMACResponse{
		Result: hmac,
	})
}

func (s server) Sign(w http.ResponseWriter, r *http.Request) {
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPSignEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	var req structs.SignParameters
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http sign bind error", errors.CodeApiHTTPSign))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signature, err := s.transit.Sign(r.Context(), &req, engineName)
	if err != nil {
		log.Debugf("Error generating sign: %v", err)
		log.Error(errors.Wrap(err, "http transit call sign error", errors.CodeApiHTTPSign))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, signature)
}

func (s server) VerifySigned(w http.ResponseWriter, r *http.Request) {
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPVerifySignEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}

	var req structs.VerificationRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http verify sign bind error", errors.CodeApiHTTPVerifySign))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	verificationResult, err := s.transit.VerifySign(r.Context(), &req, engineName)
	if err != nil {
		log.Debugf("Error validating signature %v", err)
		log.Error(errors.Wrap(err, "http transit call verify sign error", errors.CodeApiHTTPVerifySign))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, verificationResult)
}

func (s server) Health(w http.ResponseWriter, r *http.Request) {
	successResponse(w, s.health.Check(r.Context()))
}

func (s server) Rewrap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req structs.RewrapRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http rewrap key bind error", errors.CodeApiHTTPRewrapKey))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPRewrapKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	result, err := s.transit.Rewrap(ctx, req.KeyName, engineName, transit.BatchRequestItem{
		Context:    req.Context,
		Plaintext:  req.PlainText,
		Nonce:      req.Nonce,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call rewrap key error", errors.CodeApiHTTPRewrapKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.CryptoResult{
		Result: result.Ciphertext,
	})
}

func (s server) UpdateKeyConfiguration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := chi.URLParam(r, "key")
	if key == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPUpdateKeyConfigReadKey))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	var req structs.KeyConfig
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http update key config bind error", errors.CodeApiHTTPUpdateKeyConfig))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPUpdateKeyConfigEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	err := s.transit.UpdateKeyConfiguration(ctx, key, engineName, transit.KeyConfiguration{
		MinDecryptionVersion: utils.NullInt64FromPtr(req.MinDecryptionVersion),
		MinEncryptionVersion: utils.NullInt64FromPtr(req.MinEncryptionVersion),
		DeletionAllowed:      utils.NullBoolFromPtr(req.DeletionAllowed),
		Exportable:           utils.NullBoolFromPtr(req.Exportable),
		AllowPlaintextBackup: utils.NullBoolFromPtr(req.AllowPlaintextBackup),
	})
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call update key config error", errors.CodeApiHTTPUpdateKeyConfig))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.Empty{})
}

func (s server) RotateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key := chi.URLParam(r, "key")
	if key == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPRotateKeyReadKey))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	var req structs.RotateRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http rotate key bind error", errors.CodeApiHTTPRotateKey))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPRotateKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	err := s.transit.Rotate(ctx, key, engineName)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call rotate key error", errors.CodeApiHTTPRotateKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.Empty{})
}

func (s server) ExportKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyType := chi.URLParam(r, "keyType")
	if keyType == "" {
		log.Error(errors.New("key type not found", errors.CodeApiHTTPExportKeyReadKeyType))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	keyName := chi.URLParam(r, "keyName")
	if keyName == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPExportKeyReadKeyName))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	version := chi.URLParam(r, "version")
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPExportKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	export, err := s.transit.Export(ctx, keyName, engineName, keyType, version)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call export key error", errors.CodeApiHTTPExportKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}

	marshal, err := json.Marshal(export)
	if err != nil {
		log.Error(errors.Wrap(err, "http export key result marshal error", errors.CodeApiHTTPExportKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}

	successResponse(w, structs.ExportResult{
		Result: string(marshal),
	})
}

func (s server) BackupKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyName := chi.URLParam(r, "keyName")
	if keyName == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPBackupKeyReadKeyName))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPBackupKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	result, err := s.transit.Backup(ctx, keyName, engineName)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call backup key error", errors.CodeApiHTTPBackupKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.BackupResult{
		Result: result,
	})
}

func (s server) RestoreKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyName := chi.URLParam(r, "keyName")
	if keyName == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPRestoreKeyReadKeyName))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	var req structs.RestoreRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http restore key bind error", errors.CodeApiHTTPRestoreKey))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPRestoreKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	err := s.transit.Restore(ctx, keyName, engineName, req.Backup64, req.Force)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call restore key error", errors.CodeApiHTTPRestoreKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.Empty{})
}

func (s server) GenerateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyType := chi.URLParam(r, "keyType")
	if keyType == "" {
		log.Error(errors.New("key type not found", errors.CodeApiHTTPGenerateKeyReadKeyType))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	keyName := chi.URLParam(r, "keyName")
	if keyName == "" {
		log.Error(errors.New("key not found", errors.CodeApiHTTPGenerateKeyReadKeyName))
		http.Error(w, "key not found", http.StatusBadRequest)
		return
	}
	var req structs.GenerateKeyRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http generate key bind error", errors.CodeApiHTTPGenerateKey))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPGenerateKeyEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	result, err := s.transit.GenerateKey(ctx, engineName, transit.GenerateRequest{
		Name:       keyName,
		Plaintext:  keyType,
		Context:    null.NewString(req.Context, true),
		Nonce:      null.NewString(req.Nonce, true),
		Bits:       null.NewInt64(req.Bits, true),
		KeyVersion: null.NewInt64(req.KeyVersion, true),
	})
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call generate key error", errors.CodeApiHTTPGenerateKey))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.GenerateKeyResponse{
		Ciphertext: result.Ciphertext,
		KeyVersion: result.KeyVersion,
		Plaintext:  result.Plaintext,
	})
}

func (s server) GenerateRandomBytes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bytesCountRaw := chi.URLParam(r, "bytesCount")
	if bytesCountRaw == "" {
		log.Error(errors.New("bytes count not found", errors.CodeApiHTTPGenerateRandomBytesBytesCountMissing))
		http.Error(w, "bytes count not found", http.StatusBadRequest)
		return
	}
	bytesCount, err := strconv.Atoi(bytesCountRaw)
	if err != nil {
		log.Error(errors.New("bytes count invalid format", errors.CodeApiHTTPGenerateRandomBytesBytesCountFormat))
		http.Error(w, "bytes count not found", http.StatusBadRequest)
		return
	}
	var req structs.GenerateBytesRequest
	if err := bind(r, &req); err != nil {
		log.Error(errors.Wrap(err, "http generate random bytes bind error", errors.CodeApiHTTPGenerateRandomBytes))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engineName := r.Context().Value(ctxKeyEngine).(string)
	if engineName == "" {
		log.Error(errors.New("http missing engine name", errors.CodeApiHTTPGenerateRandomBytesEngineName))
		http.Error(w, "missing engine name", http.StatusBadRequest)
		return
	}
	result, err := s.transit.GenerateRandomBytes(ctx, req.UrlBytes, req.Format, bytesCount)
	if err != nil {
		log.Error(errors.Wrap(err, "http transit call generate random bytes error", errors.CodeApiHTTPGenerateRandomBytes))
		http.Error(w, "internal server error "+err.Error(), http.StatusBadRequest)
		return
	}
	successResponse(w, structs.GenerateBytesResponse{
		Result: result,
	})
}

type EncryptionServer interface {
	chi.Router

	CreateKey(w http.ResponseWriter, r *http.Request)
	ReadKey(w http.ResponseWriter, r *http.Request)
	DeleteKey(w http.ResponseWriter, r *http.Request)
	ListKeys(w http.ResponseWriter, r *http.Request)
	Encrypt(w http.ResponseWriter, r *http.Request)
	Decrypt(w http.ResponseWriter, r *http.Request)
	Hash(w http.ResponseWriter, r *http.Request)
	GenerateHMAC(w http.ResponseWriter, r *http.Request)
	Sign(w http.ResponseWriter, r *http.Request)
	VerifySigned(w http.ResponseWriter, r *http.Request)
	Rewrap(w http.ResponseWriter, r *http.Request)
	UpdateKeyConfiguration(w http.ResponseWriter, r *http.Request)
	RotateKey(w http.ResponseWriter, r *http.Request)
	ExportKey(w http.ResponseWriter, r *http.Request)
	BackupKey(w http.ResponseWriter, r *http.Request)
	RestoreKey(w http.ResponseWriter, r *http.Request)
	GenerateKey(w http.ResponseWriter, r *http.Request)
	GenerateRandomBytes(w http.ResponseWriter, r *http.Request)
	Health(w http.ResponseWriter, r *http.Request)

	Init()
	checkSecretEngineExists(next http.Handler) http.Handler
}
