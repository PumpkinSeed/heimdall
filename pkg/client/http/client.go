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

func (c *proxyClient) Health(ctx context.Context, in *structs.HealthRequest) (*structs.HealthResponse, error) {
	for _, cl := range c.cs {
		if cl.Address() == in.Address {
			return cl.Health(ctx, in)
		}
	}
	return nil, errors.New("invalid address", errors.CodeClientHttp)
}

func (h httpClient) getEngineName(ctx context.Context) string {
	en := ctx.Value(engineNameHeader).(string)
	if en == "" {
		return defaultEnginePath
	}
	return en
}
