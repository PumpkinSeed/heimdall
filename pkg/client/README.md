## Heimdall client (Go)

#### Package

```
go get github.com/PumpkinSeed/heimdall
```

#### Usage

Encrypt/Decrypt example

```go
package anything

import (
	"context"

	"github.com/PumpkinSeed/heimdall/pkg/client"
	"github.com/PumpkinSeed/heimdall/pkg/client/grpc"
	"github.com/PumpkinSeed/heimdall/pkg/structs"
)

func main() {
	hclient := client.New(grpc.Options{
		// Add more endpoints so the client can load-balance with round-robin algorithm
		URLs: []string{"10.0.0.1:9090", "10.0.0.2:9090"},
		TLS:  false,
	})
	
	var key = "test"
	hclient.CreateKey(context.Background(), &structs.Key{Name: key})
	// output: error
	hclient.ReadKey(context.Background(), key)
	// output: Key struct, error

	var plaintext = "test secret"
	result, err := hclient.Encrypt(context.Background(), &structs.EncryptRequest{
		KeyName:    key,
		PlainText:  plaintext,
	})
	// output: structs.CryptoResult, error

	result, err := hclient.Decrypt(context.TODO(), &structs.DecryptRequest{
		KeyName:    key,
		Ciphertext: result.Result,
	})
	// output: structs.CryptoResult, error
}
```