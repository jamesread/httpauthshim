package hasmtls

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
	log "github.com/sirupsen/logrus"
)

// CheckUserFromMtls extracts user information from the client certificate in a TLS connection.
// It supports extracting username from CN or SAN fields, and groups from certificate extensions.
// validateMtlsRequest checks if mTLS request is valid
func validateMtlsRequest(context *authpublic.AuthCheckingContext, mtls authpublic.MtlsConfig) (*x509.Certificate, bool) {
	if !mtls.Enabled || context.Request.TLS == nil {
		return nil, false
	}

	if len(context.Request.TLS.PeerCertificates) == 0 {
		if mtls.RequireClientCert {
			log.Debug("mTLS: Client certificate required but not present")
		}
		return nil, false
	}

	return context.Request.TLS.PeerCertificates[0], true
}

func CheckUserFromMtls(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	mtls := context.Config.Mtls

	clientCert, ok := validateMtlsRequest(context, mtls)
	if !ok {
		return nil
	}

	user := &authpublic.AuthenticatedUser{
		Provider: "mtls",
	}

	// Extract username based on configuration
	username := extractUsername(mtls, clientCert)
	if username == "" {
		log.Debug("mTLS: Could not extract username from certificate")
		return nil
	}
	user.Username = username

	// Extract groups based on configuration
	user.UsergroupLine = extractGroups(mtls, clientCert)

	return user
}

// extractUsername extracts the username from the client certificate based on configuration
// extractUsernameFromEmail extracts username from email address, optionally stripping domain
func extractUsernameFromEmail(email string, stripDomain bool) string {
	if stripDomain {
		parts := strings.Split(email, "@")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return email
}

// extractUsernameFromOID attempts to extract username from custom OID
func extractUsernameFromOID(mtls authpublic.MtlsConfig, cert *x509.Certificate) string {
	if mtls.UsernameOID == "" {
		return ""
	}
	return extractFromCustomOID(cert, mtls.UsernameOID)
}

// extractUsernameFromSANEmail attempts to extract username from SAN email
func extractUsernameFromSANEmail(mtls authpublic.MtlsConfig, cert *x509.Certificate) string {
	if !mtls.UsernameFromSANEmail || len(cert.EmailAddresses) == 0 {
		return ""
	}
	return extractUsernameFromEmail(cert.EmailAddresses[0], mtls.UsernameStripEmailDomain)
}

// extractUsernameFromCN extracts username from Common Name
func extractUsernameFromCN(mtls authpublic.MtlsConfig, cert *x509.Certificate) string {
	if mtls.UsernameFromCN || (mtls.UsernameOID == "" && !mtls.UsernameFromSANEmail) {
		return cert.Subject.CommonName
	}
	return ""
}

func extractUsername(mtls authpublic.MtlsConfig, cert *x509.Certificate) string {
	// Priority: Custom OID > SAN Email > CN
	if username := extractUsernameFromOID(mtls, cert); username != "" {
		return username
	}
	if username := extractUsernameFromSANEmail(mtls, cert); username != "" {
		return username
	}
	return extractUsernameFromCN(mtls, cert)
}

// extractGroupsFromOID extracts groups from a custom OID
func extractGroupsFromOID(mtls authpublic.MtlsConfig, cert *x509.Certificate) []string {
	if mtls.GroupOID == "" {
		return nil
	}

	groupValue := extractFromCustomOID(cert, mtls.GroupOID)
	if groupValue == "" {
		return nil
	}

	// Split by separator if configured
	if mtls.GroupSeparator != "" {
		return strings.Split(groupValue, mtls.GroupSeparator)
	}
	return []string{groupValue}
}

// extractGroupsFromSANDNS extracts groups from SAN DNS names
func extractGroupsFromSANDNS(mtls authpublic.MtlsConfig, cert *x509.Certificate) []string {
	if !mtls.GroupFromSANDNS {
		return nil
	}

	var groups []string
	for _, dns := range cert.DNSNames {
		// Optionally filter by prefix
		if mtls.GroupSANPrefix == "" || strings.HasPrefix(dns, mtls.GroupSANPrefix) {
			groups = append(groups, dns)
		}
	}
	return groups
}

// extractGroups extracts groups from the client certificate based on configuration
func extractGroups(mtls authpublic.MtlsConfig, cert *x509.Certificate) string {
	var groups []string

	// Extract from custom OID if configured
	if oidGroups := extractGroupsFromOID(mtls, cert); oidGroups != nil {
		groups = append(groups, oidGroups...)
	}

	// Extract from SAN DNS names if configured
	if dnsGroups := extractGroupsFromSANDNS(mtls, cert); dnsGroups != nil {
		groups = append(groups, dnsGroups...)
	}

	// Extract from SAN email addresses if configured
	if mtls.GroupFromSANEmail {
		groups = append(groups, cert.EmailAddresses...)
	}

	// Extract from OU (Organizational Unit) if configured
	if mtls.GroupFromOU {
		groups = append(groups, cert.Subject.OrganizationalUnit...)
	}

	// Join groups with space (standard format)
	return strings.Join(groups, " ")
}

// extractFromCustomOID extracts a value from a custom OID in the certificate extensions
// decodeExtensionValue attempts to decode extension value as string
func decodeExtensionValue(value []byte) string {
	// Try to decode as UTF-8 string
	var str string
	rest, err := asn1.Unmarshal(value, &str)
	if err == nil && len(rest) == 0 {
		return str
	}

	// Try as printable string
	var printableString string
	rest, err = asn1.Unmarshal(value, &printableString)
	if err == nil && len(rest) == 0 {
		return printableString
	}

	// Return raw bytes as string if all else fails
	return string(value)
}

func extractFromCustomOID(cert *x509.Certificate, oidString string) string {
	// Parse OID
	oid, err := parseOID(oidString)
	if err != nil {
		log.WithError(err).Debugf("mTLS: Failed to parse OID: %s", oidString)
		return ""
	}

	// Search through certificate extensions
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return decodeExtensionValue(ext.Value)
		}
	}

	return ""
}

// parseOID parses an OID string (e.g., "1.2.840.113549.1.9.1") into an asn1.ObjectIdentifier
func parseOID(oidString string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(oidString, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		var num int
		if _, err := fmt.Sscanf(part, "%d", &num); err != nil {
			return nil, fmt.Errorf("invalid OID component: %s", part)
		}
		oid[i] = num
	}
	return oid, nil
}
