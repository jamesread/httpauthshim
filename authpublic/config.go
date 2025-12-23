package authpublic

import (
	"os"
	"path/filepath"
)

type Config struct {
	Jwt JwtConfig `yaml:"jwt"`

	LocalUsers LocalUsersConfig `yaml:"localUsers"`

	OAuth2Providers   map[string]*OAuth2Provider `yaml:"oauth2Providers"`
	OAuth2RedirectURL string                     `yaml:"oauth2RedirectUrl"`

	InsecureAllowDumpOAuth2UserData bool `yaml:"insecureAllowDumpOAuth2UserData"`

	AccessControlLists []AccessControlList `yaml:"accessControlLists"`

	HttpHeader HttpHeaderConfig `yaml:"httpHeader"`

	// BaseDir is the base directory for storing auth-related files (sessions, etc.)
	// If not set, defaults to ~/.config/auth/ or the value of AUTH_HOME environment variable
	BaseDir string `yaml:"baseDir"`

	// LocalSessionCookieName is the name of the cookie used for local authentication sessions
	// Defaults to "auth-sid-local" if not set
	LocalSessionCookieName string `yaml:"localSessionCookieName"`

	// OAuth2SessionCookieName is the name of the cookie used for OAuth2 authentication sessions
	// Defaults to "auth-sid-oauth" if not set
	OAuth2SessionCookieName string `yaml:"oauth2SessionCookieName"`

	// SessionFileName is the name of the file used to store sessions
	// Defaults to "sessions.yaml" if not set
	SessionFileName string `yaml:"sessionFileName"`

	// Mtls is the mTLS (Mutual TLS) configuration
	Mtls MtlsConfig `yaml:"mtls"`
}

// JwtConfig contains configuration for JWT authentication
type JwtConfig struct {
	// CertsURL is the URL for JWKS (JSON Web Key Set) endpoint
	CertsURL string `yaml:"certsUrl"`

	// PubKeyPath is the path to a local RSA public key file
	PubKeyPath string `yaml:"pubKeyPath"`

	// HmacSecret is the HMAC secret for JWT verification
	HmacSecret string `yaml:"hmacSecret"`

	// Aud is the expected audience claim
	Aud string `yaml:"aud"`

	// Issuer is the expected issuer claim
	Issuer string `yaml:"issuer"`

	// ClaimUsername is the JWT claim key for username
	ClaimUsername string `yaml:"claimUsername"`

	// ClaimUserGroup is the JWT claim key for user groups
	ClaimUserGroup string `yaml:"claimUserGroup"`

	// CookieName is the name of the cookie containing the JWT token
	CookieName string `yaml:"cookieName"`

	// Header is the HTTP header name containing the JWT token (e.g., "Authorization")
	Header string `yaml:"header"`

	// InsecureAllowDumpJwtClaims allows dumping JWT claims in debug logs (insecure)
	InsecureAllowDumpJwtClaims bool `yaml:"insecureAllowDumpJwtClaims"`
}

// HttpHeaderConfig contains configuration for trusted HTTP header authentication
type HttpHeaderConfig struct {
	// Username is the HTTP header name containing the username
	Username string `yaml:"username"`

	// UserGroup is the HTTP header name containing the user group
	UserGroup string `yaml:"userGroup"`

	// UserGroupSep is the separator for multiple groups in the user group header
	UserGroupSep string `yaml:"userGroupSep"`
}

// MtlsConfig contains configuration for mTLS (Mutual TLS) authentication
type MtlsConfig struct {
	// Enabled enables mTLS authentication
	Enabled bool `yaml:"enabled"`

	// RequireClientCert requires a client certificate to be present
	// If false, mTLS will only authenticate if a certificate is present
	RequireClientCert bool `yaml:"requireClientCert"`

	// Username extraction options
	// UsernameFromCN extracts username from Common Name (CN) field
	UsernameFromCN bool `yaml:"usernameFromCN"`

	// UsernameFromSANEmail extracts username from SAN email addresses
	UsernameFromSANEmail bool `yaml:"usernameFromSANEmail"`

	// UsernameStripEmailDomain strips the domain part from email addresses
	// Only applies when UsernameFromSANEmail is true
	UsernameStripEmailDomain bool `yaml:"usernameStripEmailDomain"`

	// UsernameOID extracts username from a custom OID in certificate extensions
	// Format: "1.2.840.113549.1.9.1" (example: emailAddress OID)
	UsernameOID string `yaml:"usernameOID"`

	// Group extraction options
	// GroupFromOU extracts groups from Organizational Unit (OU) fields
	GroupFromOU bool `yaml:"groupFromOU"`

	// GroupFromSANEmail extracts groups from SAN email addresses
	GroupFromSANEmail bool `yaml:"groupFromSANEmail"`

	// GroupFromSANDNS extracts groups from SAN DNS names
	GroupFromSANDNS bool `yaml:"groupFromSANDNS"`

	// GroupSANPrefix filters SAN DNS names by prefix (only applies to GroupFromSANDNS)
	GroupSANPrefix string `yaml:"groupSANPrefix"`

	// GroupOID extracts groups from a custom OID in certificate extensions
	GroupOID string `yaml:"groupOID"`

	// GroupSeparator separates multiple groups in a single OID value
	// Default: empty (treat as single group)
	GroupSeparator string `yaml:"groupSeparator"`
}

type LocalUsersConfig struct {
	Enabled bool         `yaml:"enabled"`
	Users   []*LocalUser `yaml:"users"`
}

type LocalUser struct {
	Username  string `yaml:"username"`
	Usergroup string `yaml:"usergroup"`
	Password  string `yaml:"password"`
}

type OAuth2Provider struct {
	Name               string   `yaml:"name"`
	Title              string   `yaml:"title"`
	Icon               string   `yaml:"icon"`
	UsernameField      string   `yaml:"usernameField"`
	UserGroupField     string   `yaml:"userGroupField"`
	WhoamiUrl          string   `yaml:"whoamiUrl"`
	TokenUrl           string   `yaml:"tokenUrl"`
	AuthUrl            string   `yaml:"authUrl"`
	ClientID           string   `yaml:"clientId"`
	ClientSecret       string   `yaml:"clientSecret"`
	Scopes             []string `yaml:"scopes"`
	InsecureSkipVerify bool     `yaml:"insecureSkipVerify"`
	RedirectURL        string   `yaml:"redirectUrl"`
	CertBundlePath     string   `yaml:"certBundlePath"`
	CallbackTimeout    int      `yaml:"callbackTimeout"`
	AddToGroup         string   `yaml:"addToGroup"` // Adds all users authenticated with this provider to a dummy usergroup with this name
}

// GetDir returns the base directory for storing auth-related files.
// Priority: 1) BaseDir config field, 2) AUTH_HOME env var, 3) ~/.config/auth/
func (c *Config) GetDir() string {
	if c.BaseDir != "" {
		return c.BaseDir
	}

	if dir := os.Getenv("AUTH_HOME"); dir != "" {
		return dir
	}

	// Default fallback to ~/.config/auth/
	home, err := os.UserHomeDir()
	if err != nil {
		// If we can't get home directory, use current directory
		return "."
	}

	return filepath.Join(home, ".config", "auth")
}

// GetLocalSessionCookieName returns the cookie name for local sessions, with default fallback
func (c *Config) GetLocalSessionCookieName() string {
	if c.LocalSessionCookieName != "" {
		return c.LocalSessionCookieName
	}
	return "auth-sid-local"
}

// GetOAuth2SessionCookieName returns the cookie name for OAuth2 sessions, with default fallback
func (c *Config) GetOAuth2SessionCookieName() string {
	if c.OAuth2SessionCookieName != "" {
		return c.OAuth2SessionCookieName
	}
	return "auth-sid-oauth"
}

// GetSessionFileName returns the session file name, with default fallback
func (c *Config) GetSessionFileName() string {
	if c.SessionFileName != "" {
		return c.SessionFileName
	}
	return "sessions.yaml"
}

type AccessControlList struct {
	Name            string   `yaml:"name"`
	MatchUsernames  []string `yaml:"matchUsernames"`
	MatchUsergroups []string `yaml:"matchUsergroups"`
}

func (c *Config) FindUserByUsername(username string) *AuthenticatedUser {
	for _, user := range c.LocalUsers.Users {
		if user.Username == username {
			return &AuthenticatedUser{
				Username:      user.Username,
				UsergroupLine: user.Usergroup,
				Provider:      "local",
			}
		}
	}

	return nil
}
