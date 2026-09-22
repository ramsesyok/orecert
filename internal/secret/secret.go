// Package secret はパスワード取得とPKCS#8秘密鍵の暗号化を担当します。
package secret

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/youmark/pkcs8"
	"golang.org/x/term"
)

const Iterations = 600000

func Read(source string) ([]byte, error) { return resolve(source, prompt) }

func resolve(source string, ask func() ([]byte, error)) ([]byte, error) {
	var password []byte
	switch {
	case source == "prompt:":
		for range 3 {
			p, err := ask()
			if err != nil {
				return nil, err
			}
			if len(p) > 0 {
				return p, nil
			}
			clear(p)
		}
		return nil, errors.New("password must not be empty (3 attempts)")
	case strings.HasPrefix(source, "file:"):
		data, err := readLimited(strings.TrimPrefix(source, "file:"))
		if err != nil {
			return nil, fmt.Errorf("read password file: %w", err)
		}
		password = bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	default:
		password = []byte(source)
	}
	if len(password) == 0 {
		return nil, errors.New("password must not be empty")
	}
	return password, nil
}

func prompt() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("password prompt requires a terminal; use file:<path> for automation")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return p, err
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1024*1024 {
		clear(b)
		return nil, errors.New("input file exceeds 1 MiB")
	}
	return b, nil
}

func Encode(key any, encrypted bool, password []byte) ([]byte, error) {
	var block pem.Block
	if encrypted {
		if len(password) == 0 {
			return nil, errors.New("password must not be empty")
		}
		der, err := pkcs8.MarshalPrivateKey(key, password, &pkcs8.Opts{Cipher: pkcs8.AES256CBC, KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: Iterations, HMACHash: crypto.SHA256}})
		if err != nil {
			return nil, err
		}
		block = pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}
	} else {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			block = pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, err
			}
			block = pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		case ed25519.PrivateKey:
			der, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, err
			}
			block = pem.Block{Type: "PRIVATE KEY", Bytes: der}
		default:
			return nil, errors.New("unsupported private key")
		}
	}
	defer clear(block.Bytes)
	return pem.EncodeToMemory(&block), nil
}

func ReadKey(path, source string) (any, error) {
	data, err := readLimited(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		if err := validateEncrypted(block.Bytes); err != nil {
			return nil, err
		}
		if source == "" {
			source = "prompt:"
		}
		password, err := Read(source)
		if err != nil {
			return nil, err
		}
		defer clear(password)
		return pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
	default:
		return nil, errors.New("unsupported private key PEM type")
	}
}

// 破損したCBC入力と過大なKDFパラメータを依存ライブラリに渡さないよう検証します。
func validateEncrypted(der []byte) error {
	invalid := errors.New("unsupported or invalid encrypted PKCS#8 parameters")
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || info.Algorithm.Algorithm.String() != "1.2.840.113549.1.5.13" {
		return invalid
	}
	var params struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}
	rest, err = asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params)
	if err != nil || len(rest) != 0 || params.KDF.Algorithm.String() != "1.2.840.113549.1.5.12" || params.Cipher.Algorithm.String() != "2.16.840.1.101.3.4.1.42" {
		return invalid
	}
	var kdf struct {
		Salt       []byte
		Iterations int
		KeyLength  int                      `asn1:"optional"`
		PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	rest, err = asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf)
	if err != nil || len(rest) != 0 || len(kdf.Salt) < 8 || len(kdf.Salt) > 64 || kdf.Iterations < 1 || kdf.Iterations > 10000000 || kdf.KeyLength != 0 && kdf.KeyLength != 32 {
		return invalid
	}
	var iv []byte
	rest, err = asn1.Unmarshal(params.Cipher.Parameters.FullBytes, &iv)
	if err != nil || len(rest) != 0 || len(iv) != 16 || len(info.Data) == 0 || len(info.Data)%16 != 0 {
		return invalid
	}
	return nil
}
