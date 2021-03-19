# Heimdall

- AES-CBC-256 with Shamir's secret splitted IV
- Shamir package provided by [hashicorp vault](https://pkg.go.dev/github.com/hashicorp/vault/shamir)
- After the split we can start each node with one of the piece of the splitted IV. They can broadcast it between each other.
- Consider XChaCha20-Poly1305
- Type prefix for which algorithm used. Ex 4e5467fc -> AES-CBC (Easy to migrate)
