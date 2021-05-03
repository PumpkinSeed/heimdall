package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync/atomic"

	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
	"github.com/hashicorp/vault/api"
	"google.golang.org/grpc"
)

const defaultEnginePath = "transit/"

type Options struct {
	*api.Config
	EngineName string
	URLs       []string
	Token []string
}

func (o *Options) Setup() client.Client {
	if o.Config == nil {
		o.Config = api.DefaultConfig()
	}
	if len(o.URLs) != len(o.Token) {
		panic("missing client token")
	}
	c := proxyClient{o: *o}
	vaultClient, _ := api.NewClient(o.Config)
	if len(o.URLs) == 0 {
		c.cs = []*httpClient{{vaultClient}}
	} else {
		cs := make([]*httpClient, 0, len(o.URLs))
		for i, url := range o.URLs {
			o.Config.Address = url
			duplicate, err := vaultClient.Clone()
			if err != nil {
				panic(err)
			}
			if o.Token[i] != "" {
				duplicate.AddHeader("token", o.Token[i])
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

func (c *proxyClient) Health(ctx context.Context, in *structs.HealthRequest) (*structs.HealthResponse, error) {
	for _, cl := range c.cs {
		if cl.Address() == in.Address {
			return cl.Health(ctx, in)
		}
	}
	return nil, errors.New("invalid address")
}

func (c *proxyClient) next() structs.EncryptionClient {
	n := atomic.AddUint32(&c.nxt, 1)
	return c.cs[(int(n)-1)%len(c.cs)]
}

func (c *proxyClient) CreateKey(ctx context.Context, key *structs.Key) (*structs.KeyResponse, error) {
	key.EngineName = c.o.EngineName
	return c.next().CreateKey(ctx, key)
}

func (c *proxyClient) ReadKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	return c.next().ReadKey(ctx, &structs.KeyName{Name: keyName, EngineName: c.o.EngineName})
}

func (c *proxyClient) DeleteKey(ctx context.Context, keyName string) (*structs.KeyResponse, error) {
	return c.next().DeleteKey(ctx, &structs.KeyName{Name: keyName, EngineName: c.o.EngineName})
}

func (c *proxyClient) ListKeys(ctx context.Context) (*structs.KeyListResponse, error) {
	return c.next().ListKeys(ctx, &structs.Empty{EngineName: c.o.EngineName})
}

func (c *proxyClient) Encrypt(ctx context.Context, req *structs.EncryptRequest) (*structs.CryptoResult, error) {
	req.EngineName = c.o.EngineName
	return c.next().Encrypt(ctx, req)
}

func (c *proxyClient) Decrypt(ctx context.Context, req *structs.DecryptRequest) (*structs.CryptoResult, error) {
	req.EngineName = c.o.EngineName
	return c.next().Decrypt(ctx, req)
}

func (c *proxyClient) Hash(ctx context.Context, req *structs.HashRequest) (*structs.HashResponse, error) {
	req.EngineName = c.o.EngineName
	return c.next().Hash(ctx, req)
}

func (c *proxyClient) GenerateHMAC(ctx context.Context, req *structs.HMACRequest) (*structs.HMACResponse, error) {
	req.EngineName = c.o.EngineName
	return c.next().GenerateHMAC(ctx, req)
}

func (c *proxyClient) Sign(ctx context.Context, req *structs.SignParameters) (*structs.SignResponse, error) {
	req.EngineName = c.o.EngineName
	return c.next().Sign(ctx, req)
}

func (c *proxyClient) VerifySigned(ctx context.Context, req *structs.VerificationRequest) (*structs.VerificationResponse, error) {
	req.EngineName = c.o.EngineName
	return c.next().VerifySigned(ctx, req)
}

// wrapper for vault client, implements the EncryptionClient interface
type httpClient struct {
	*api.Client
}

func (h httpClient) Health(ctx context.Context, in *structs.HealthRequest, opts ...grpc.CallOption) (*structs.HealthResponse, error) {
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/health"))
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
		var resp structs.HealthResponse
		if err := json.Unmarshal(res, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	}
	return nil, err
}

func (h httpClient) CreateKey(ctx context.Context, in *structs.Key, opts ...grpc.CallOption) (*structs.KeyResponse, error) {
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/key", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/%s/key/%s", in.EngineName, in.Name))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodDelete, fmt.Sprintf("/%s/key/%s", in.EngineName, in.Name))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodGet, fmt.Sprintf("/%s/key", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/encrypt", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/decrypt", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/hash", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/hmac", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/sign", in.EngineName))
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
	if in.EngineName == "" {
		in.EngineName = defaultEnginePath
	}
	r := h.NewRequest(http.MethodPost, fmt.Sprintf("/%s/verify", in.EngineName))
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
