package revoke

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"orecert/internal/issue"
)

// Config は revoke 用設定です。
type Config struct {
	CA struct {
		Key  string `mapstructure:"key"`
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Profile は CN を保持します。
type Profile struct {
	CN string `mapstructure:"cn"`
}

// Revoke は証明書を失効させ CRL を更新します。
func Revoke(cfg Config, prof Profile) error {
	if prof.CN == "" || strings.Contains(prof.CN, "..") || strings.ContainsAny(prof.CN, "/\\") {
		return issue.ErrInvalidCN
	}
	if cfg.CA.Key == "" {
		cfg.CA.Key = filepath.FromSlash("certs/ca/key.pem")
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}
	crlPath := filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem")
	certPath := filepath.Join("certs", prof.CN, "cert.pem")

	cert, err := issue.ReadCert(certPath)
	if err != nil {
		return err
	}
	caCert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		return err
	}
	keyAny, err := issue.ReadKey(cfg.CA.Key)
	if err != nil {
		return err
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return errors.New("ca key is not signer")
	}

	data, err := os.ReadFile(crlPath)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return errors.New("invalid crl pem")
	}
	var revoked []x509.RevocationListEntry
	number := big.NewInt(1)
	if len(blk.Bytes) > 0 {
		rl, err := x509.ParseRevocationList(blk.Bytes)
		if err != nil {
			return err
		}
		revoked = rl.RevokedCertificateEntries
		if rl.Number != nil {
			number = new(big.Int).Add(rl.Number, big.NewInt(1))
		}
	}
	revoked = append(revoked, x509.RevocationListEntry{SerialNumber: cert.SerialNumber, RevocationTime: time.Now()})

	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        caCert.SignatureAlgorithm,
		RevokedCertificateEntries: revoked,
		Number:                    number,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 30),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, signer)
	if err != nil {
		return err
	}
	return os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644)
}
