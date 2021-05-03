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
    - `--grpc`: determine the bind address of grpc connection (optional, default: `0.0.0.0:9090`)
    - `--http`: determine the bind address of http connection (optional, default: `0.0.0.0:8080`)
    - `--socket`: determine the unix socket location (optional, default: `/tmp/heimdall.sock`)
    - `--threshold`: threshold of the shamir key unseal limit (optional, default: `3`)
    - `--consul-address`: determine the physical backend's address
    - `--consul-token`: determine the physical backend's credentials
    - `--in-memory`: starts the server with in-memory backend, so it can run in as a standalone instance (WARNING: insecure)
    - `--default-engine-path`: determine the default secret engine's path if there are multiple engines available (optional, default: `transit/`)
    - `--verbose`: start in verbose mode (optional)
    - `--log-output`: set the output of the log (optional, options.: syslog, stdout)
    - `--log-additional`: set additional configuration for log (optional, ex.: for syslog: ``)
- init (initialization phase of Heimdall, do it only once if the system has a physical backend which didn't initialize yet)
    - `--socket`: determine the unix socket location (optional, default: `/tmp/heimdall.sock`)
    - `--threshold`: threshold of the shamir key unseal limit (optional, default: `3`)
    - `--total-shares`: total shares of the initialized shamir key (optional, default: `5`)
- unseal (unseal a sealed Heimdall)
    - `--socket`: determine the unix socket location (optional, default: `/tmp/heimdall.sock`)

#### Command examples

Start the server scenario:

```
// tty1
heimdall server --consul-address 127.0.0.1:8500 --consul-token {{TOKEN}}

// tty2
heimdall unseal {{KEY1}}
heimdall unseal {{KEY2}}
heimdall unseal {{KEY3}}
```

Provide all flags scenario:

```
// tty1
heimdall server \
    --consul-address 127.0.0.1:8500 \
    --consul-token {{TOKEN}} \
    --http 0.0.0.0:8080 \
    --grpc 0.0.0.0:9090 \
    --socket /somewhere/else/heimdall.sock \
    --threshold 4 \
    --default-engine-path difftransit/ \
    --log-output syslog \
    --log-additional ""

// tty2
heimdall init \
    --socket /somewhere/else/heimdall.sock \
    --threshold 4 \
    --total-shares 5

heimdall unseal --socket /somewhere/else/heimdall.sock {{KEY1}}
heimdall unseal --socket /somewhere/else/heimdall.sock {{KEY2}}
heimdall unseal --socket /somewhere/else/heimdall.sock {{KEY3}}
heimdall unseal --socket /somewhere/else/heimdall.sock {{KEY4}}
```

#### Go client

The documentation is available under the [client directory](pkg/client/README.md).
