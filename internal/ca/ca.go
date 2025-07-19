package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Config holds minimal settings for CA generation.
type Config struct {
	DefaultAlgo string `mapstructure:"default_algo"`
	DefaultDays int    `mapstructure:"default_days"`
	Overwrite   bool   `mapstructure:"overwrite"`
	CA          struct {
		Key  string `mapstructure:"key"`
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

var ErrExists = errors.New("ca files exist and overwrite disabled")

// InitCA generates CA key and certificate according to config.
func InitCA(cfg Config) error {
	if cfg.DefaultAlgo == "" {
		cfg.DefaultAlgo = "rsa"
	}
	if cfg.DefaultDays == 0 {
		cfg.DefaultDays = 825
	}
	if cfg.CA.Key == "" {
		cfg.CA.Key = filepath.FromSlash("certs/ca/key.pem")
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}

	if !cfg.Overwrite {
		if Exists(cfg.CA.Key) || Exists(cfg.CA.Cert) {
			return ErrExists
		}
	}

	if err := os.MkdirAll(filepath.Dir(cfg.CA.Key), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.CA.Cert), 0755); err != nil {
		return err
	}

	priv, pub, err := GenerateKey(cfg.DefaultAlgo)
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               PkixName(),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, cfg.DefaultDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return err
	}

	if err := WriteKey(cfg.CA.Key, priv); err != nil {
		return err
	}

	if err := os.WriteFile(cfg.CA.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
		return err
	}

	crlPath := filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem")
	if !Exists(crlPath) {
		if err := os.WriteFile(crlPath, []byte("-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"), 0644); err != nil {
			return err
		}
	}

	return nil
}

// Exists はファイルの有無を確認します。
func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// GenerateKey は CA 用の鍵ペアを生成します。
func GenerateKey(algo string) (any, any, error) {
	switch algo {
	case "rsa", "":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case "ecdsa":
		priv, err := ecdsa.GenerateKey(EllipticP256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, &priv.PublicKey, nil
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	default:
		return nil, nil, errors.New("unsupported algo")
	}
}

// WriteKey は秘密鍵を PEM 形式で保存します。
func WriteKey(path string, key any) error {
	var block *pem.Block
	switch k := key.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	case ed25519.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return err
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	default:
		return errors.New("unknown key type")
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func randomSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}

// PkixName は CA 証明書用の固定 Subject を返します。
func PkixName() pkix.Name {
	return pkix.Name{CommonName: "orecert root CA"}
}

// EllipticP256 は P-256 曲線を返します。
func EllipticP256() elliptic.Curve {
	return elliptic.P256()
}
