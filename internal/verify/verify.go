package verify

import (
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"orecert/internal/issue"
	"orecert/internal/revoke"
	"orecert/internal/safefile"
)

// Config は verify 用設定です。
type Config struct {
	Type    string
	DNSName string
	SkipCRL bool
	CA      struct {
		Cert string `mapstructure:"cert"`
	} `mapstructure:"ca"`
}

// Profile はプロファイルから CN のみを利用します。
type Profile struct {
	CN string `mapstructure:"cn"`
}

// エラー定義
var (
	ErrExpired = errors.New("expired")
	ErrVerify  = errors.New("verify failed")
)

// Verify は証明書と CA のチェーン検証を行います。
func Verify(cfg Config, prof Profile) error {
	if safefile.ValidateCN(prof.CN) != nil {
		return issue.ErrInvalidCN
	}
	if cfg.CA.Cert == "" {
		cfg.CA.Cert = filepath.FromSlash("certs/ca/cert.pem")
	}
	certPath := filepath.Join("certs", prof.CN, "cert.pem")
	if _, err := safefile.CertificateDir(prof.CN, cfg.CA.Cert); err != nil {
		return err
	}
	cert, err := issue.ReadCert(certPath)
	if err != nil {
		return err
	}
	caCert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		return err
	}
	if time.Now().After(cert.NotAfter) {
		return ErrExpired
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	typ := cfg.Type
	if typ == "" || typ == "auto" {
		typ = "server"
		hasServer, hasClient := false, false
		for _, usage := range cert.ExtKeyUsage {
			hasServer = hasServer || usage == x509.ExtKeyUsageServerAuth
			hasClient = hasClient || usage == x509.ExtKeyUsageClientAuth
		}
		if hasClient {
			typ = "client"
			if hasServer {
				typ = "both"
			}
		}
	}
	usages := []x509.ExtKeyUsage{}
	switch typ {
	case "server":
		usages = append(usages, x509.ExtKeyUsageServerAuth)
	case "client":
		usages = append(usages, x509.ExtKeyUsageClientAuth)
	case "both":
		usages = append(usages, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	default:
		return errors.New("invalid verification type")
	}
	for _, usage := range usages {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Now(), DNSName: cfg.DNSName, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return ErrVerify
		}
	}
	if !cfg.SkipCRL {
		crl, err := revoke.ReadCRL(filepath.Join(filepath.Dir(cfg.CA.Cert), "crl.pem"), caCert, false)
		if err != nil {
			return fmt.Errorf("CRL verification: %w", err)
		}
		now := time.Now()
		if now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
			return errors.New("CRL is not current; run refresh-crl")
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
				return errors.New("certificate is revoked")
			}
		}
	}
	return nil
}
