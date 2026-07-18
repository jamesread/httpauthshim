package haslocal

import (
	"crypto/subtle"
	"strings"

	"github.com/jamesread/httpauthshim/authpublic"
	log "github.com/sirupsen/logrus"
)

// CheckUserFromApiKey authenticates a local user via Authorization: Bearer <apiKey>.
// Requires LocalUsers.Enabled and a matching non-empty ApiKey on a configured user.
func CheckUserFromApiKey(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	if !context.Config.LocalUsers.Enabled {
		return nil
	}

	token := extractBearerApiKey(context)
	if token == "" {
		return nil
	}

	return matchLocalUserApiKey(context.Config, token)
}

func extractBearerApiKey(context *authpublic.AuthCheckingContext) string {
	authHeader := context.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(authHeader, "Bearer ")
}

func matchLocalUserApiKey(cfg *authpublic.Config, token string) *authpublic.AuthenticatedUser {
	user := findLocalUserByApiKey(cfg, token)
	if user == nil {
		log.WithFields(log.Fields{
			"tokenPreview": previewApiKey(token),
		}).Debug("Local API key not found in configured users")
		return nil
	}

	authenticated := &authpublic.AuthenticatedUser{
		Username:      user.Username,
		UsergroupLine: user.Usergroup,
		Provider:      "local-apikey",
	}

	log.WithFields(log.Fields{
		"username":  authenticated.Username,
		"usergroup": authenticated.UsergroupLine,
		"provider":  authenticated.Provider,
	}).Infof("Local API key authentication successful")

	return authenticated
}

func findLocalUserByApiKey(cfg *authpublic.Config, token string) *authpublic.LocalUser {
	var matched *authpublic.LocalUser
	for _, user := range cfg.LocalUsers.Users {
		if apiKeyMatches(token, user.ApiKey) {
			matched = user
		}
	}
	return matched
}

func apiKeyMatches(provided, expected string) bool {
	if expected == "" || provided == "" {
		return false
	}
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func previewApiKey(token string) string {
	if len(token) > 8 {
		return token[:8] + "..."
	}
	return token
}
