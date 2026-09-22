package verify

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"orecert/internal/ca"
	"orecert/internal/issue"
	"orecert/internal/revoke"
	"os"
	"testing"
	"time"
)

func TestClientAndRevocation(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := ca.InitCA(ca.Config{DefaultAlgo: "ecdsa"}); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(issue.Config{}, issue.Profile{CN: "client", Algo: "ecdsa"}, "client"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(Config{}, Profile{CN: "client"}); err != nil {
		t.Fatal(err)
	}
	if err := revoke.Revoke(revoke.Config{}, revoke.Profile{CN: "client"}); err != nil {
		t.Fatal(err)
	}
	if err := Verify(Config{}, Profile{CN: "client"}); err == nil {
		t.Fatal("失効済み証明書を許可しました")
	}
}

func TestCRLValidityAndExplicitUsage(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := ca.InitCA(ca.Config{DefaultAlgo: "ecdsa"}); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(issue.Config{}, issue.Profile{CN: "host", Algo: "ecdsa"}, "server"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(Config{Type: "client"}, Profile{CN: "host"}); err == nil {
		t.Fatal("誤った用途")
	}
	if err := Verify(Config{Type: "invalid"}, Profile{CN: "host"}); err == nil {
		t.Fatal("未定義の用途")
	}
	cert, err := issue.ReadCert("certs/ca/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := issue.ReadKey("certs/ca/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range []time.Duration{-48 * time.Hour, 48 * time.Hour} {
		now := time.Now().Add(delta)
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, cert, key.(crypto.Signer))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("certs/ca/crl.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644); err != nil {
			t.Fatal(err)
		}
		if err := Verify(Config{}, Profile{CN: "host"}); err == nil {
			t.Fatal("時刻が不正なCRL")
		}
		if err := Verify(Config{SkipCRL: true}, Profile{CN: "host"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMissingCRLFails(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := ca.InitCA(ca.Config{DefaultAlgo: "ecdsa"}); err != nil {
		t.Fatal(err)
	}
	if err := issue.Issue(issue.Config{}, issue.Profile{CN: "host", Algo: "ecdsa"}, "server"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove("certs/ca/crl.pem"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(Config{}, Profile{CN: "host"}); err == nil {
		t.Fatal("CRL欠落を拒否しませんでした")
	}
}
