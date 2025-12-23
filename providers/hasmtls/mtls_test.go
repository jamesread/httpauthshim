package hasmtls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jamesread/httpauthshim/authpublic"
	"github.com/stretchr/testify/assert"
)

func createTestCert(t *testing.T, cn string, email []string, dns []string, ou []string) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: ou,
		},
		EmailAddresses: email,
		DNSNames:       dns,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestCheckUserFromMtls_Disabled(t *testing.T) {
	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled: false,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.Nil(t, user)
}

func TestCheckUserFromMtls_NoTLS(t *testing.T) {
	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled: true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.Nil(t, user)
}

func TestCheckUserFromMtls_FromCN(t *testing.T) {
	cert := createTestCert(t, "testuser", nil, nil, nil)

	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled:        true,
			UsernameFromCN: true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.NotNil(t, user)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "mtls", user.Provider)
}

func TestCheckUserFromMtls_FromSANEmail(t *testing.T) {
	cert := createTestCert(t, "", []string{"user@example.com"}, nil, nil)

	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled:             true,
			UsernameFromSANEmail: true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.NotNil(t, user)
	assert.Equal(t, "user@example.com", user.Username)
}

func TestCheckUserFromMtls_FromSANEmail_StripDomain(t *testing.T) {
	cert := createTestCert(t, "", []string{"user@example.com"}, nil, nil)

	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled:                 true,
			UsernameFromSANEmail:     true,
			UsernameStripEmailDomain: true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.NotNil(t, user)
	assert.Equal(t, "user", user.Username)
}

func TestCheckUserFromMtls_GroupsFromOU(t *testing.T) {
	cert := createTestCert(t, "testuser", nil, nil, []string{"admin", "developers"})

	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled:        true,
			UsernameFromCN: true,
			GroupFromOU:    true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.NotNil(t, user)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "admin developers", user.UsergroupLine)
}

func TestCheckUserFromMtls_GroupsFromSANDNS(t *testing.T) {
	cert := createTestCert(t, "testuser", nil, []string{"group1.example.com", "group2.example.com"}, nil)

	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled:        true,
			UsernameFromCN: true,
			GroupFromSANDNS: true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.NotNil(t, user)
	assert.Equal(t, "testuser", user.Username)
	assert.Contains(t, user.UsergroupLine, "group1.example.com")
	assert.Contains(t, user.UsergroupLine, "group2.example.com")
}

func TestCheckUserFromMtls_RequireClientCert(t *testing.T) {
	cfg := &authpublic.Config{
		Mtls: authpublic.MtlsConfig{
			Enabled:           true,
			RequireClientCert:  true,
			UsernameFromCN:     true,
		},
	}

	req := httptest.NewRequest("GET", "/", nil)
	// No TLS connection state
	context := &authpublic.AuthCheckingContext{
		Request: req,
		Config:  cfg,
	}

	user := CheckUserFromMtls(context)
	assert.Nil(t, user)
}

func TestExtractFromCustomOID(t *testing.T) {
	// Create a certificate with a custom extension
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Use emailAddress OID (1.2.840.113549.1.9.1) as test
	emailOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	emailValue := "custom@example.com"
	emailBytes, err := asn1.Marshal(emailValue)
	if err != nil {
		t.Fatalf("Failed to marshal email: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    emailOID,
				Value: emailBytes,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Test extraction
	result := extractFromCustomOID(cert, "1.2.840.113549.1.9.1")
	assert.Equal(t, emailValue, result)
}
