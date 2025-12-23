package hasbasic

import (
	"encoding/base64"
	"strings"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/providers/haslocal"
	log "github.com/sirupsen/logrus"
)

// CheckUserFromBasicAuth extracts and validates HTTP Basic authentication credentials.
// It reads the Authorization header, decodes the base64-encoded username:password,
// and validates against the configured local users using Argon2id password hashing.
func CheckUserFromBasicAuth(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	if !context.Config.BasicAuth.Enabled {
		return nil
	}

	username, password, ok := extractBasicAuthCredentials(context)
	if !ok {
		return nil
	}

	if !validateBasicAuthCredentials(context, username, password) {
		return nil
	}

	return createAuthenticatedUserFromBasicAuth(context, username)
}

// extractBasicAuthCredentials extracts username and password from Authorization header
func extractBasicAuthCredentials(context *authpublic.AuthCheckingContext) (string, string, bool) {
	authHeader := context.Request.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", false
	}

	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", false
	}

	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Debug("HTTP Basic: Failed to decode base64 credentials")
		return "", "", false
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		log.Debug("HTTP Basic: Invalid credential format (expected username:password)")
		return "", "", false
	}

	return parts[0], parts[1], true
}

// validateBasicAuthCredentials validates username and password against local users
func validateBasicAuthCredentials(context *authpublic.AuthCheckingContext, username, password string) bool {
	if !haslocal.CheckUserPassword(context.Config, username, password) {
		log.WithFields(log.Fields{
			"username": username,
		}).Debug("HTTP Basic: Invalid credentials")
		return false
	}
	return true
}

// createAuthenticatedUserFromBasicAuth creates an AuthenticatedUser from validated credentials
func createAuthenticatedUserFromBasicAuth(context *authpublic.AuthCheckingContext, username string) *authpublic.AuthenticatedUser {
	cfgUser := context.Config.FindUserByUsername(username)
	if cfgUser == nil {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("HTTP Basic: User authenticated but not found in config")
		return nil
	}

	user := &authpublic.AuthenticatedUser{
		Username:      cfgUser.Username,
		UsergroupLine: cfgUser.UsergroupLine,
		Provider:      "basic",
	}

	log.WithFields(log.Fields{
		"username":  user.Username,
		"usergroup": user.UsergroupLine,
		"provider":  user.Provider,
	}).Infof("HTTP Basic authentication successful")

	return user
}
