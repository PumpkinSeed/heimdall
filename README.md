# Heimdall

The Vigilant Guardian of Data. Opt-in replacement for Hashicorp Vault's transit secret engine. This is a simplified version of the transit engine and ONLY works with that engine.

### Usage

#### Installation

Pre-built binaries are located under the [releases](https://github.com/PumpkinSeed/heimdall/releases) for certain architectures:

- Linux (AMD64, ARM64)
- Windows (AMD64)
- Darwin (AMD64)

... or build your own:

```
go build -o heimdall main.go
```

#### Automation

At the moment we aren't have a secure way for the automation of the boot process. The `unseal` process should be done manually. So using auto-scale or auto-restart tools won't work since the system starts in a sealed status.

#### Flags

There are three commands at the moment. (server, init, unseal)

- server (starts the actual server with http and grpc allowed by default)
    - `--grpc`:
    - `--http`: 
    - `--socket`:
    - `--threshold`:
    - `--consul-address`:
    - `--consul-token`:
    - `--in-memory`:
    - `--default-engine-path`:
    - `--verbose`:
    - `--log-output`:
    - `--log-additional`:
- init ()
    - `--socket`:
    - `--threshold`:
    - `--total-shares`:
- unseal ()
    - `--socket`:

#### Go client

The documentation is available under the [client directory](pkg/client/README.md).
