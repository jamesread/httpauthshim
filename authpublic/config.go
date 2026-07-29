package authpublic

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/jamesread/httpauthshim/sessions"
)

type Config struct {
	// OIDCProviders is a map of OIDC provider configurations
	OIDCProviders map[string]*OIDCProvider `yaml:"oidcProviders"`

	OAuth2Providers map[string]*OAuth2Provider `yaml:"oauth2Providers"`

	// OAuth2SessionCookieName is the name of the cookie used for OAuth2 authentication sessions
	// Defaults to "auth-sid-oauth" if not set
	OAuth2SessionCookieName string `yaml:"oauth2SessionCookieName"`

	// BaseDir is the base directory for storing auth-related files (sessions, etc.)
	// If not set, defaults to ~/.config/auth/ or the value of AUTH_HOME environment variable
	BaseDir string `yaml:"baseDir"`

	// LocalSessionCookieName is the name of the cookie used for local authentication sessions
	// Defaults to "auth-sid-local" if not set
	LocalSessionCookieName string `yaml:"localSessionCookieName"`

	OAuth2RedirectURL string `yaml:"oauth2RedirectUrl"`

	// OIDCRedirectURL is the redirect URL for OIDC callbacks
	OIDCRedirectURL string `yaml:"oidcRedirectUrl"`

	// SessionFileName is the name of the file used to store sessions
	// Defaults to "sessions.yaml" if not set
	SessionFileName string `yaml:"sessionFileName"`

	Jwt JwtConfig `yaml:"jwt"`

	// Mtls is the mTLS (Mutual TLS) configuration
	Mtls MtlsConfig `yaml:"mtls"`

	// BearerToken is the Bearer token authentication configuration
	BearerToken BearerTokenConfig `yaml:"bearerToken"`

	AccessControlLists []AccessControlList `yaml:"accessControlLists"`

	HttpHeader HttpHeaderConfig `yaml:"httpHeader"`

	LocalUsers LocalUsersConfig `yaml:"localUsers"`

	// SessionIdleTimeoutSeconds is the inactivity timeout for sessions (OWASP idle timeout).
	// Default: 1800 (30 minutes). Set to -1 to disable idle timeout.
	SessionIdleTimeoutSeconds int `yaml:"sessionIdleTimeoutSeconds"`

	// SessionAbsoluteTimeoutSeconds is the maximum session lifetime from creation (OWASP absolute timeout).
	// Default: 28800 (8 hours).
	SessionAbsoluteTimeoutSeconds int `yaml:"sessionAbsoluteTimeoutSeconds"`

	InsecureAllowDumpOAuth2UserData bool `yaml:"insecureAllowDumpOAuth2UserData"`

	// OAuth2DisablePKCE disables PKCE for the authorization code flow.
	// PKCE is enabled by default and should only be disabled for legacy providers.
	OAuth2DisablePKCE bool `yaml:"oauth2DisablePkce"`

	// BasicAuth is the HTTP Basic authentication configuration
	BasicAuth BasicAuthConfig `yaml:"basicAuth"`

	// TrustForwardedHeaders allows X-Forwarded-Proto to influence Secure cookie
	// decisions when OAuth2AllowInsecureCookies is true. Only enable behind a
	// reverse proxy that strips client-supplied forwarded headers.
	TrustForwardedHeaders bool `yaml:"trustForwardedHeaders"`

	// OAuth2AllowInsecureCookies allows Secure=false on cleartext HTTP.
	// Intended for local development only. Default false (Secure cookies always).
	OAuth2AllowInsecureCookies bool `yaml:"oauth2AllowInsecureCookies"`

	// OAuth2CookieSecure forces the Secure flag on auth cookies.
	// Secure is already the default; this remains for explicit force-on.
	OAuth2CookieSecure bool `yaml:"oauth2CookieSecure"`
}

// JwtConfig contains configuration for JWT authentication
type JwtConfig struct {
	// CertsURL is the URL for JWKS (JSON Web Key Set) endpoint
	CertsURL string `yaml:"certsUrl"`

	// PubKeyPath is the path to a local RSA public key file
	PubKeyPath string `yaml:"pubKeyPath"`

	// HmacSecret is the HMAC secret for JWT verification
	HmacSecret string `yaml:"hmacSecret"`

	// Aud is the expected audience claim (required when JWT verification is configured)
	Aud string `yaml:"aud"`

	// Issuer is the expected issuer claim (required when JWT verification is configured)
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

	// TrustedProxyCIDRs is required when Enabled is true. Requests must come from
	// one of these CIDRs (matched against RemoteAddr) or trusted-header auth is ignored.
	TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`

	// Enabled enables trusted HTTP header authentication (default: false).
	// Only enable when requests pass through a reverse proxy that strips or sets
	// these headers; never expose this provider directly to untrusted clients.
	Enabled bool `yaml:"enabled"`
}

// MtlsConfig contains configuration for mTLS (Mutual TLS) authentication
type MtlsConfig struct {
	// UsernameOID extracts username from a custom OID in certificate extensions
	// Format: "1.2.840.113549.1.9.1" (example: emailAddress OID)
	UsernameOID string `yaml:"usernameOID"`

	// GroupSANPrefix filters SAN DNS names by prefix (only applies to GroupFromSANDNS)
	GroupSANPrefix string `yaml:"groupSANPrefix"`

	// GroupOID extracts groups from a custom OID in certificate extensions
	GroupOID string `yaml:"groupOID"`

	// GroupSeparator separates multiple groups in a single OID value
	// Default: empty (treat as single group)
	GroupSeparator string `yaml:"groupSeparator"`

	// Enabled enables mTLS authentication
	Enabled bool `yaml:"enabled"`

	// RequireClientCert requires a client certificate to be present
	// If false, mTLS will only authenticate if a certificate is present
	RequireClientCert bool `yaml:"requireClientCert"`

	// UsernameFromCN extracts username from Common Name (CN) field
	UsernameFromCN bool `yaml:"usernameFromCN"`

	// UsernameFromSANEmail extracts username from SAN email addresses
	UsernameFromSANEmail bool `yaml:"usernameFromSANEmail"`

	// UsernameStripEmailDomain strips the domain part from email addresses
	// Only applies when UsernameFromSANEmail is true
	UsernameStripEmailDomain bool `yaml:"usernameStripEmailDomain"`

	// GroupFromOU extracts groups from Organizational Unit (OU) fields
	GroupFromOU bool `yaml:"groupFromOU"`

	// GroupFromSANEmail extracts groups from SAN email addresses
	GroupFromSANEmail bool `yaml:"groupFromSANEmail"`

	// GroupFromSANDNS extracts groups from SAN DNS names
	GroupFromSANDNS bool `yaml:"groupFromSANDNS"`
}

// BasicAuthConfig contains configuration for HTTP Basic authentication
type BasicAuthConfig struct {
	// Enabled enables HTTP Basic authentication
	Enabled bool `yaml:"enabled"`
}

// BearerTokenConfig contains configuration for Bearer token authentication
type BearerTokenConfig struct {
	// Tokens is a map of bearer tokens to user information
	Tokens map[string]*BearerTokenUser `yaml:"tokens"`

	// Header is the HTTP header name containing the Bearer token (defaults to "Authorization")
	Header string `yaml:"header"`

	// Enabled enables Bearer token authentication
	Enabled bool `yaml:"enabled"`
}

// BearerTokenUser contains user information for a Bearer token
type BearerTokenUser struct {
	// Username is the username associated with this token
	Username string `yaml:"username"`

	// Usergroup is the usergroup(s) associated with this token (space-separated)
	Usergroup string `yaml:"usergroup"`
}

// OIDCProvider contains configuration for an OIDC provider
// OIDC extends OAuth2 with ID tokens and standardized endpoints
type OIDCProvider struct {
	// AddToGroup adds all users authenticated with this provider to a dummy usergroup with this name
	AddToGroup string `yaml:"addToGroup"`

	// ClientID is the OAuth2/OIDC client ID
	ClientID string `yaml:"clientId"`

	// ClientSecret is the OAuth2/OIDC client secret
	ClientSecret string `yaml:"clientSecret"`

	// IssuerURL is the OIDC issuer URL (e.g., https://accounts.google.com)
	// If set, discovery document will be fetched from {IssuerURL}/.well-known/openid-configuration
	IssuerURL string `yaml:"issuerUrl"`

	// AuthUrl is the authorization URL (optional if IssuerURL is set)
	AuthUrl string `yaml:"authUrl"`

	// TokenUrl is the token URL (optional if IssuerURL is set)
	TokenUrl string `yaml:"tokenUrl"`

	// UserInfoUrl is the userinfo endpoint URL (optional if IssuerURL is set)
	UserInfoUrl string `yaml:"userInfoUrl"`

	// UsernameField is the field name in userinfo/ID token for username (defaults to "sub" or "preferred_username")
	UsernameField string `yaml:"usernameField"`

	// UserGroupField is the field name in userinfo/ID token for usergroup
	UserGroupField string `yaml:"userGroupField"`

	// ClaimUserGroup is the JWT claim key for user groups in ID token
	ClaimUserGroup string `yaml:"claimUserGroup"`

	// CertBundlePath is the path to a CA certificate bundle for TLS verification
	CertBundlePath string `yaml:"certBundlePath"`

	// ClaimUsername is the JWT claim key for username in ID token (defaults to "sub" or "preferred_username")
	ClaimUsername string `yaml:"claimUsername"`

	// Scopes are the OAuth2 scopes to request (should include "openid" for OIDC)
	Scopes []string `yaml:"scopes"`

	// CallbackTimeout is the timeout for callback requests in seconds
	CallbackTimeout int `yaml:"callbackTimeout"`

	// InsecureSkipVerify skips TLS certificate verification
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
}

type LocalUsersConfig struct {
	Users   []*LocalUser `yaml:"users"`
	Enabled bool         `yaml:"enabled"`
}

type LocalUser struct {
	Username  string `yaml:"username"`
	Usergroup string `yaml:"usergroup"`
	Password  string `yaml:"password"`
	// ApiKey is an optional shared secret accepted via Authorization: Bearer <apiKey>
	ApiKey string `yaml:"apiKey"`
}

type OAuth2Provider struct {
	ClientID       string `yaml:"clientId"`
	ClientSecret   string `yaml:"clientSecret"`
	Icon           string `yaml:"icon"`
	UsernameField  string `yaml:"usernameField"`
	UserGroupField string `yaml:"userGroupField"`
	WhoamiUrl      string `yaml:"whoamiUrl"`
	Title          string `yaml:"title"`
	TokenUrl       string `yaml:"tokenUrl"`
	Name           string `yaml:"name"`
	AuthUrl        string `yaml:"authUrl"`
	// AddToGroup adds all users authenticated with this provider to a dummy usergroup with this name
	AddToGroup         string   `yaml:"addToGroup"`
	CertBundlePath     string   `yaml:"certBundlePath"`
	RedirectURL        string   `yaml:"redirectUrl"`
	Scopes             []string `yaml:"scopes"`
	CallbackTimeout    int      `yaml:"callbackTimeout"`
	InsecureSkipVerify bool     `yaml:"insecureSkipVerify"`
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

// OAuth2PKCEEnabled reports whether PKCE should be used for OAuth2 flows.
func (c *Config) OAuth2PKCEEnabled() bool {
	if c == nil {
		return true
	}
	return !c.OAuth2DisablePKCE
}

// CookieSecure reports whether auth cookies should set the Secure flag.
// Default is true. Cleartext HTTP is only allowed when OAuth2AllowInsecureCookies
// is set (local development). X-Forwarded-Proto is only honored when
// TrustForwardedHeaders is also set.
func (c *Config) CookieSecure(r *http.Request) bool {
	if c == nil || c.OAuth2CookieSecure || !c.OAuth2AllowInsecureCookies {
		return true
	}
	return cookieSecureFromRequest(r, c.TrustForwardedHeaders)
}

func cookieSecureFromRequest(r *http.Request, trustForwarded bool) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return trustForwarded && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// GetOAuth2SessionCookieName returns the cookie name for OAuth2 sessions, with default fallback
func (c *Config) GetOAuth2SessionCookieName() string {
	if c.OAuth2SessionCookieName != "" {
		return c.OAuth2SessionCookieName
	}
	return "auth-sid-oauth"
}

// GetSessionIdleTimeoutSeconds returns the idle timeout in seconds.
// Default is 30 minutes (OWASP low-risk range). A negative config value disables idle timeout.
func (c *Config) GetSessionIdleTimeoutSeconds() int {
	if c == nil || c.SessionIdleTimeoutSeconds == 0 {
		return sessions.DefaultIdleTimeoutSeconds
	}
	if c.SessionIdleTimeoutSeconds < 0 {
		return 0
	}
	return c.SessionIdleTimeoutSeconds
}

// GetSessionAbsoluteTimeoutSeconds returns the absolute session lifetime in seconds.
// Default is 8 hours (OWASP recommended range for full-day office use).
func (c *Config) GetSessionAbsoluteTimeoutSeconds() int {
	if c == nil || c.SessionAbsoluteTimeoutSeconds <= 0 {
		return sessions.DefaultAbsoluteTimeoutSeconds
	}
	return c.SessionAbsoluteTimeoutSeconds
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
