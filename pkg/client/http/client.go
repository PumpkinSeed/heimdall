package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync/atomic"

	"github.com/PumpkinSeed/heimdall/internal/errors"
	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// TODO update changes
const (
	defaultEnginePath = "transit/"
	engineNameHeader  = "engineName"
)

type Options struct {
	*api.Config
	URLs       []string
	EngineName string
	Token      string
}

func (o *Options) Setup() client.Client {
	if o.Config == nil {
		o.Config = api.DefaultConfig()
	}
	c := proxyClient{o: *o}
	vaultClient, err := api.NewClient(o.Config)
	if err != nil {
		log.Error(errors.Wrap(err, "vault client create error", errors.CodeClientHttpSetupCreateClient))
	}
	if o.Token != "" {
		vaultClient.AddHeader("authorization", o.Token)
	}
	if len(o.URLs) == 0 {
		c.cs = []*httpClient{{vaultClient}}
	} else {
		cs := make([]*httpClient, 0, len(o.URLs))
		for _, url := range o.URLs {
			o.Config.Address = url
			duplicate, err := vaultClient.Clone()
			if err != nil {
				log.Error(errors.Wrap(err, "vault client clone error", errors.CodeClientHttpSetupCloneClient))
				continue
			}
			if o.Token != "" {
				duplicate.AddHeader("authorization", o.Token)
			}
			cs = append(cs, &httpClient{duplicate})
		}
		c.cs = cs
	}
	return &c
}

// proxyClient implements the Client interface
type proxyClient struct {
	o   Options
	cs  []*httpClient
	nxt uint32
}

func (c *proxyClient) next() structs.EncryptionClient {
	n := atomic.AddUint32(&c.nxt, 1)
	return c.cs[(int(n)-1)%len(c.cs)]
}

func (c *proxyClient) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	createKey, err := c.next().CreateKey(buildEngineNameInterceptor(ctx, c.o.EngineName), key)
	if err != nil {
		return nil, errors.Wrap(err, "http client create key error", errors.CodeClientHttpCreateKey)
	}
	return createKey, nil
}

func (c *proxyClient) ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	key, err := c.next().ReadKey(buildEngineNameInterceptor(ctx, c.o.EngineName), &structs.KeyName{Name: keyName})
	if err != nil {
		return nil, errors.Wrap(err, "http client read key error", errors.CodeClientHttpReadKey)
	}
	return key, nil
}

func (c *proxyClient) DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	key, err := c.next().DeleteKey(buildEngineNameInterceptor(ctx, c.o.EngineName), &structs.KeyName{Name: keyName})
	if err != nil {
		return nil, errors.Wrap(err, "http client delete key error", errors.CodeClientHttpDeleteKey)
	}
	return key, nil
}

func (c *proxyClient) ListKeys(ctx context.Context) (*structs.KeyListResponse, error) {
	keys, err := c.next().ListKeys(buildEngineNameInterceptor(ctx, c.o.EngineName), &structs.Empty{})
	if err != nil {
		return nil, errors.Wrap(err, "http client list keys error", errors.CodeClientHttpListKey)
	}
	return keys, nil
}

func (c *proxyClient) Encrypt(ctx context.Context, req *structs.EncryptRequest) (*structs.CryptoResult, error) {
	encrypt, err := c.next().Encrypt(buildEngineNameInterceptor(ctx, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client encrypt error", errors.CodeClientHttpEncrypt)
	}
	return encrypt, nil
}

func (c *proxyClient) Decrypt(ctx context.Context, req *structs.DecryptRequest) (*structs.CryptoResult, error) {
	decrypt, err := c.next().Decrypt(buildEngineNameInterceptor(ctx, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client decrypt error", errors.CodeClientHttpDecrypt)
	}
	return decrypt, nil
}

func (c *proxyClient) Hash(ctx context.Context, req *structs.HashRequest) (*structs.HashResponse, error) {
	hash, err := c.next().Hash(buildEngineNameInterceptor(ctx, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client hash error", errors.CodeClientHttpHash)
	}
	return hash, nil
}

func (c *proxyClient) GenerateHMAC(ctx context.Context, req *structs.HMACRequest) (*structs.HMACResponse, error) {
	hmac, err := c.next().GenerateHMAC(buildEngineNameInterceptor(ctx, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client hmac error", errors.CodeClientHttpHmac)
	}
	return hmac, nil
}

func (c *proxyClient) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	sign, err := c.next().Sign(buildEngineNameInterceptor(ctx, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client sign error", errors.CodeClientHttpSign)
	}
	return sign, nil
}

func (c *proxyClient) VerifySigned(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	signed, err := c.next().VerifySigned(buildEngineNameInterceptor(ctx, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client verify sign error", errors.CodeClientHttpVerifySign)
	}
	return signed, nil
}

func (c *proxyClient) Rewrap(ctx context.Context, req *structs.RewrapRequest) (*structs.CryptoResult, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().Rewrap(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client rewrap error", errors.CodeClientHttpRewrap)
	}
	return out, nil
}

func (c *proxyClient) UpdateKeyConfiguration(ctx context.Context, req *structs.KeyConfig) (*structs.Empty, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().UpdateKeyConfiguration(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client update key config error", errors.CodeClientHttpUpdateKeyConfig)
	}
	return out, nil
}

func (c *proxyClient) RotateKey(ctx context.Context, req *structs.RotateRequest) (*structs.Empty, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().RotateKey(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client rotate error", errors.CodeClientHttpRotateKey)
	}
	return out, nil
}

func (c *proxyClient) ExportKey(ctx context.Context, req *structs.ExportRequest) (*structs.ExportResult, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().ExportKey(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client export error", errors.CodeClientHttpExport)
	}
	return out, nil
}

func (c *proxyClient) BackupKey(ctx context.Context, req *structs.BackupRequest) (*structs.BackupResult, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().BackupKey(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client backup error", errors.CodeClientHttpBackup)
	}
	return out, nil
}

func (c *proxyClient) RestoreKey(ctx context.Context, req *structs.RestoreRequest) (*structs.Empty, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().RestoreKey(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client restore error", errors.CodeClientHttpRestore)
	}
	return out, nil
}

func (c *proxyClient) GenerateKey(ctx context.Context, req *structs.GenerateKeyRequest) (*structs.GenerateKeyResponse, error) {
	req.EngineName = c.o.EngineName
	out, err := c.next().GenerateKey(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "http client generate key error", errors.CodeClientHttpGenerate)
	}
	return out, nil
}

func (c *proxyClient) GenerateRandomBytes(ctx context.Context, req *structs.GenerateBytesRequest) (*structs.GenerateBytesResponse, error) {
	out, err := c.next().GenerateRandomBytes(context.WithValue(ctx, engineNameHeader, c.o.EngineName), req)
	if err != nil {
		return nil, errors.Wrap(err, "http client generate random bytes error", errors.CodeClientHttpGenerateRandomBytes)
	}
	return out, nil
}

func (c *proxyClient) Health(ctx context.Context, in *structs.HealthRequest) (*structs.HealthResponse, error) {
	for _, cl := range c.cs {
		if cl.Address() == in.Address {
			return cl.Health(ctx, in)
		}
	}
	return nil, errors.New("invalid address", errors.CodeClientHttp)
}

func buildEngineNameInterceptor(ctx context.Context, engineName string) context.Context {
	return context.WithValue(ctx, engineNameHeader, engineName)
}

// wrapper for vault client, implements the EncryptionClient interface
type httpClient struct {
	*api.Client
}

func (h httpClient) Health(ctx context.Context, in *structs.HealthRequest, opts ...grpc.CallOption) (*structs.HealthResponse, error) {
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/health"))
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, errors.Wrap(err, "http client vault raw request with context", errors.CodeClientHttpHealthVaultRequest)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "http client read error", errors.CodeClientHttpHealthRead)
		}
		var resp structs.HealthResponse
		if err := json.Unmarshal(res, &resp); err != nil {
			return nil, errors.Wrap(err, "http client read error", errors.CodeClientHttpHealthUnmarshal)
		}
		return &resp, nil
	}
	return nil, err
}

func (h httpClient) CreateKey(ctx context.Context, in *structs.Key, opts ...grpc.CallOption) (*structs.KeyResponse, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/key", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.KeyResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) ReadKey(ctx context.Context, in *structs.KeyName, opts ...grpc.CallOption) (*structs.KeyResponse, error) {
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/%s/key/%s", h.getEngineName(ctx), in.Name))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.KeyResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) DeleteKey(ctx context.Context, in *structs.KeyName, opts ...grpc.CallOption) (*structs.KeyResponse, error) {
	r := h.NewRequest(http.MethodDelete, fmt.Sprintf("/%s/key/%s", h.getEngineName(ctx), in.Name))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}

	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.KeyResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) ListKeys(ctx context.Context, in *structs.Empty, opts ...grpc.CallOption) (*structs.KeyListResponse, error) {
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/%s/key", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.KeyListResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) Encrypt(ctx context.Context, in *structs.EncryptRequest, opts ...grpc.CallOption) (*structs.CryptoResult, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/encrypt", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.CryptoResult
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) Decrypt(ctx context.Context, in *structs.DecryptRequest, opts ...grpc.CallOption) (*structs.CryptoResult, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/decrypt", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.CryptoResult
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) Hash(ctx context.Context, in *structs.HashRequest, opts ...grpc.CallOption) (*structs.HashResponse, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/hash", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.HashResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) GenerateHMAC(ctx context.Context, in *structs.HMACRequest, opts ...grpc.CallOption) (*structs.HMACResponse, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/hmac", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.HMACResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) Sign(ctx context.Context, in *structs.SignParameters, opts ...grpc.CallOption) (*structs.SignResponse, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/sign", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.SignResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) VerifySigned(ctx context.Context, in *structs.VerificationRequest, opts ...grpc.CallOption) (*structs.VerificationResponse, error) {
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/verify", h.getEngineName(ctx)))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.VerificationResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) Rewrap(ctx context.Context, in *structs.RewrapRequest, opts ...grpc.CallOption) (*structs.CryptoResult, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/rewrap/%s", in.EngineName, in.KeyName))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.CryptoResult
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}
		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) UpdateKeyConfiguration(ctx context.Context, in *structs.KeyConfig, opts ...grpc.CallOption) (*structs.Empty, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/keys/%s/config", in.EngineName, in.KeyName))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &structs.Empty{}, nil
	}
	return nil, err
}

func (h httpClient) RotateKey(ctx context.Context, in *structs.RotateRequest, opts ...grpc.CallOption) (*structs.Empty, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/keys/%s/rotate", in.EngineName, in.KeyName))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &structs.Empty{}, nil
	}
	return nil, err
}

func (h httpClient) ExportKey(ctx context.Context, in *structs.ExportRequest, opts ...grpc.CallOption) (*structs.ExportResult, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/%s/export/%s/%s/%s", in.EngineName, in.ExportType, in.KeyName, in.Version))
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.ExportResult
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}

		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) BackupKey(ctx context.Context, in *structs.BackupRequest, opts ...grpc.CallOption) (*structs.BackupResult, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/%s/backup/%s", in.EngineName, in.KeyName))
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.BackupResult
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}

		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) RestoreKey(ctx context.Context, in *structs.RestoreRequest, opts ...grpc.CallOption) (*structs.Empty, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/restore/%s", in.EngineName, in.KeyName))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return &structs.Empty{}, nil
	}
	return nil, err
}

func (h httpClient) GenerateKey(ctx context.Context, in *structs.GenerateKeyRequest, opts ...grpc.CallOption) (*structs.GenerateKeyResponse, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/datakey/%s/%s", in.EngineName, in.Plaintext, in.Name))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.GenerateKeyResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}

		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) GenerateRandomBytes(ctx context.Context, in *structs.GenerateBytesRequest, opts ...grpc.CallOption) (*structs.GenerateBytesResponse, error) {
	engineName := ctx.Value(engineNameHeader)
	if engineName == "" {
		engineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/random/%d", engineName, in.BytesCount))
	if err := r.SetJSONBody(in); err != nil {
		return nil, err
	}
	resp, err := h.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var keyResp structs.GenerateBytesResponse
		if err := json.Unmarshal(res, &keyResp); err != nil {
			return nil, err
		}

		return &keyResp, nil
	}
	return nil, err
}

func (h httpClient) getEngineName(ctx context.Context) string {
	en := ctx.Value(engineNameHeader).(string)
	if en == "" {
		return defaultEnginePath
	}
	return en
}
