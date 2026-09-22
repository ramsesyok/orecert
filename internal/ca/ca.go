package ca

import (
	"crypto"
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
	"orecert/internal/safefile"
	"orecert/internal/secret"
	"os"
	"path/filepath"
	"time"
)

// Config はCA生成の設定です。
type Config struct {
	DefaultAlgo string `mapstructure:"default_algo"`
	DefaultDays int    `mapstructure:"default_days"`
	Overwrite   bool   `mapstructure:"overwrite"`
	CA          struct {
		Key  string `mapstructure:"key"`
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

var ErrExists = safefile.ErrExists

// InitCA はCA鍵・証明書・署名付きCRLをまとめて生成します。
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

	if cfg.DefaultDays < 1 || cfg.DefaultDays > 36500 {
		return errors.New("days must be between 1 and 36500")
	}
	crlPath := filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem")
	files := []safefile.File{{Path: cfg.CA.Key, Mode: 0600}, {Path: cfg.CA.Cert, Mode: 0644}, {Path: crlPath, Mode: 0644}}
	if err := safefile.Check(files, cfg.Overwrite); err != nil {
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

	files[0].Data, err = secret.Encode(priv, false, nil)
	if err != nil {
		return err
	}
	defer clear(files[0].Data)
	files[1].Data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	next := now.AddDate(0, 0, 30)
	if next.After(cert.NotAfter) {
		next = cert.NotAfter
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: next}, cert, priv.(crypto.Signer))
	if err != nil {
		return err
	}
	files[2].Data = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})
	return safefile.Write(files, cfg.Overwrite)
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
	data, err := secret.Encode(key, false, nil)
	if err != nil {
		return err
	}
	defer clear(data)
	return safefile.Write([]safefile.File{{Path: path, Data: data, Mode: 0600}}, true)
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
