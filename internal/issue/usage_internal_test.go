package issue

import (
	"crypto/x509"
	"testing"
)

// TestUsageByType は KeyUsage と ExtKeyUsage の組み合わせを確認します。
func TestUsageByType(t *testing.T) {
	eku, ku := usageByType("server", "rsa")
	if len(eku) != 1 || eku[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("server usage")
	}
	if ku&x509.KeyUsageDigitalSignature == 0 || ku&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatalf("server key usage")
	}

	eku, ku = usageByType("client", "rsa")
	if len(eku) != 1 || eku[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client usage")
	}
	if ku != x509.KeyUsageDigitalSignature {
		t.Fatalf("client key usage")
	}

	eku, ku = usageByType("both", "ed25519")
	if len(eku) != 2 {
		t.Fatalf("both usage")
	}
	if ku != x509.KeyUsageDigitalSignature { // ed25519 では KeyEncipherment 不要
		t.Fatalf("both key usage")
	}
}
