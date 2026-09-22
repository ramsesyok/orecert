package revoke

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"orecert/internal/issue"
	"os"
	"testing"
	"time"
)

func TestRefreshPreservesEntriesAndSignature(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	issueCert(t, dir, "host", cfg)
	if err := Revoke(cfg, Profile{CN: "host"}); err != nil {
		t.Fatal(err)
	}
	if err := Revoke(cfg, Profile{CN: "host"}); err != nil {
		t.Fatal(err)
	}
	if err := Refresh(cfg); err != nil {
		t.Fatal(err)
	}
	cert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ReadCRL("certs/ca/crl.pem", cert, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatal("重複または失効情報の喪失")
	}
	data, err := os.ReadFile("certs/ca/crl.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	block.Bytes[len(block.Bytes)-1] ^= 1
	if err := os.WriteFile("certs/ca/crl.pem", pem.EncodeToMemory(block), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Refresh(cfg); err == nil {
		t.Fatal("改ざんCRLを再署名しました")
	}
}

func TestLegacyEmptyCRLMigration(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	if err := os.WriteFile("certs/ca/crl.pem", []byte("-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCRL("certs/ca/crl.pem", cert, false); err == nil {
		t.Fatal("未署名CRLを検証で受理しました")
	}
	if err := Refresh(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCRL("certs/ca/crl.pem", cert, false); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRejectsWrongCAKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	issueCert(t, dir, "host", cfg)
	key, err := os.ReadFile("certs/host/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CA.Key, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Refresh(cfg); err == nil {
		t.Fatal("CA鍵の不一致")
	}
}

func TestCRLWrongIssuer(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := createCA(t, dir)
	cert, err := issue.ReadCert(cfg.CA.Cert)
	if err != nil {
		t.Fatal(err)
	}
	key, err := issue.ReadKey(cfg.CA.Key)
	if err != nil {
		t.Fatal(err)
	}
	clone := *cert
	clone.RawSubject = nil
	clone.Subject.CommonName = "another CA"
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)}, &clone, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("certs/ca/crl.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCRL("certs/ca/crl.pem", cert, false); err == nil {
		t.Fatal("異なる発行者のCRL")
	}
}
