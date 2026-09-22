# orecert

orecert creates a self-signed root CA, issues development server/client certificates, and exports PEM, PKCS#12 (`.p12`) and Java KeyStore (`.jks`) files.

## Build

Go **1.27.1** or newer is required. From a source checkout:

```sh
go build -o orecert .
```

On Windows, use `go build -o orecert.exe .` and invoke `./orecert.exe` in PowerShell.

## Usage

Run from the project/output directory. Configuration defaults to `.orecert.yaml` in that directory. All relative paths, including password files, are relative to the working directory.

```sh
./orecert init-ca -c .orecert.yaml
./orecert issue -c .orecert.yaml profiles/localhost.yml -t server
./orecert bundle -c .orecert.yaml profiles/localhost.yml -t all
./orecert verify -c .orecert.yaml profiles/localhost.yml --hostname localhost
```

The bundled configuration prompts for a non-empty bundle password without echoing input. For automation, use `pkcs12_password: 'file:password.txt'`. One final LF/CRLF is removed from the UTF-8 password file. Environment variables do not override configuration. Missing, malformed, unknown or invalid configuration is rejected.

```yaml
default_algo: rsa
default_days: 825
overwrite: false
pkcs12_password: 'prompt:'
ca:
  key: certs/ca/key.pem
  cert: certs/ca/cert.pem
```

To encrypt a generated PEM private key, set these fields in its profile:

```yaml
cn: localhost
san: [DNS:localhost, IP:127.0.0.1]
rsa_bits: 2048
encrypt_key: true
key_pass: 'prompt:'
```

`bundle` uses the same profile's `key_pass` to read an encrypted key. PEM encryption uses PKCS#8 / PBES2 / AES-256-CBC with PBKDF2-HMAC-SHA-256 (600,000 iterations). PKCS#12 uses the compatible Modern2023 AES profile with 600,000 iterations. `bundle --legacy` explicitly selects weaker 3DES compatibility encoding and prints a warning. RSA is the default for broad interoperability; actual Ed25519 support depends on the consuming application.

## Commands

| Command | Purpose |
| --- | --- |
| `init-ca` | Create CA key, certificate and signed empty CRL |
| `issue <profile> -t server\|client\|both` | Create key, CSR, certificate, full chain and metadata |
| `bundle <profile> -t pkcs\|jks\|all` | Export key and chain; repeated `-t` options are combined |
| `verify <profile>` | Check chain, validity, EKU and signed local CRL |
| `revoke <profile>` | Add a revocation without duplicates and refresh the CRL |
| `refresh-crl` | Renew the CRL while preserving existing revocations |
| `version` | Print the version without requiring a configuration file |

`verify -t auto` is the default; `server`, `client`, or `both` explicitly select required usages. `--hostname` additionally checks a DNS name or IP address. A missing, invalid, future-dated or expired CRL fails verification. `--skip-crl` is an explicit opt-out with a warning. Refresh the CRL before its 30-day expiry; expiry is capped at the CA's expiry.

Existing CA material is retained unless `overwrite: true` is explicitly configured. **Recreating a CA invalidates its relationship with previously issued certificates.** Normal output errors are rolled back; crashes/power loss and concurrent operations on the same output are not transactionally supported. Back up the CA before replacing it.

The tool does not install trust roots or configure revocation checking in other applications. Never distribute the CA private key. Secret outputs use mode 0600 on Unix and a protected owner/SYSTEM ACL on Windows; grant the intended service account access separately when deploying.

For existing installations, see the [migration and usage guide](docs/README-ja.md). [Original requirements](docs/requirements.md) are historical and do not describe every current behavior.

## Validation

```sh
go test ./... -count=1 "-coverpkg=./..." "-coverprofile=coverage.out"
go vet ./...
```

Run `pwsh -File scripts/check-coverage.ps1` to require at least 90% statement coverage. CI runs tests and vulnerability scans on Windows and Linux. It blocks releases if tests or the coverage gate fail.

## License

Apache 2.0.
