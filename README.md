# orecert

**orecert** is a command line tool for creating and managing self-signed certificates for local development.

## Installation

Go 1.22 or newer is required. Install with `go install`:

```bash
go install github.com/yourname/orecert@latest
```

Or clone this repository and build from source:

```bash
git clone https://github.com/yourname/orecert.git
cd orecert
go build
```

## Usage

orecert generates a certificate authority and issues server or client certificates based on YAML profiles.

```bash
orecert init-ca -c .orecert.yaml
orecert issue -c .orecert.yaml profiles/localhost.yml
```

### Subcommands

- `init-ca` – generate CA key and certificate
- `issue` – create key, CSR and certificate from a profile
- `bundle` – package PEM files into PKCS#12 or JKS
- `verify` – validate a certificate and its chain
- `revoke` – revoke a certificate and update the CRL
- `version` – show the current version

### Configuration

Settings are read from a YAML file specified with `-c` (default `.orecert.yaml`).
It defines defaults such as algorithm, validity period and bundle password.

Example:

```yaml
default_algo: rsa
default_days: 825
overwrite: false
pkcs12_password: prompt:
ca:
  key: certs/ca/key.pem
  cert: certs/ca/cert.pem
```

See [`docs/requirements.md`](docs/requirements.md) for the detailed specification.
The Japanese version of this README is available at [`docs/README-ja.md`](docs/README-ja.md).

## License

This project is licensed under the Apache 2.0 License.
