package bundle

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

// Config は bundle 用の最小設定です。
type Config struct {
	PKCS12Password string `mapstructure:"pkcs12_password"`
	CA             struct {
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Bundle は指定 CN の鍵と証明書を梱包します。
func Bundle(cfg Config, cn, typ string) error {
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}
	base := filepath.Join("certs", cn)
	keyPath := filepath.Join(base, "key.pem")
	certPath := filepath.Join(base, "cert.pem")

	key, err := readKey(keyPath)
	if err != nil {
		return err
	}
	cert, err := readCert(certPath)
	if err != nil {
		return err
	}
	caCert, err := readCert(cfg.CA.Cert)
	if err != nil {
		return err
	}

	switch typ {
	case "pkcs", "all":
		if err := writePKCS12(base, key, cert, caCert, cfg.PKCS12Password); err != nil {
			return err
		}
		if typ == "pkcs" {
			return nil
		}
		fallthrough
	case "jks":
		return writeJKS(base, key, cert, caCert, cfg.PKCS12Password)
	default:
		return errors.New("unsupported type")
	}
}

func readKey(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("invalid key pem")
	}
	switch blk.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	default:
		return x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("invalid cert pem")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func writePKCS12(base string, key any, cert, ca *x509.Certificate, password string) error {
	der, err := pkcs12.Encode(rand.Reader, key, cert, []*x509.Certificate{ca}, password)
	if err != nil {
		return err
	}
	out := filepath.Join(base, "bundle.p12")
	return os.WriteFile(out, der, 0644)
}

func writeJKS(base string, key any, cert, ca *x509.Certificate, password string) error {
	ks := keystore.New()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: []keystore.Certificate{{Type: "X509", Content: cert.Raw}, {Type: "X509", Content: ca.Raw}},
	}
	if err := ks.SetPrivateKeyEntry("orecert", entry, []byte(password)); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(base, "bundle.jks"))
	if err != nil {
		return err
	}
	defer f.Close()
	return ks.Store(f, []byte(password))
}
