package hasbearer

import (
	"strings"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
	log "github.com/sirupsen/logrus"
)

// CheckUserFromBearerToken extracts and validates Bearer token authentication.
// It reads the Authorization header (or configured header), extracts the Bearer token,
// and validates it against the configured token map.
func CheckUserFromBearerToken(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	if !context.Config.BearerToken.Enabled {
		return nil
	}

	token := extractBearerToken(context)
	if token == "" {
		return nil
	}

	return validateBearerToken(context, token)
}

// extractBearerToken extracts the Bearer token from the configured header
func extractBearerToken(context *authpublic.AuthCheckingContext) string {
	headerName := getBearerHeaderName(context.Config.BearerToken.Header)
	authHeader := context.Request.Header.Get(headerName)
	if authHeader == "" {
		return ""
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}

	return strings.TrimPrefix(authHeader, "Bearer ")
}

// getBearerHeaderName returns the header name, defaulting to "Authorization"
func getBearerHeaderName(configured string) string {
	if configured != "" {
		return configured
	}
	return "Authorization"
}

// validateBearerToken validates the token and returns an AuthenticatedUser if valid
func validateBearerToken(context *authpublic.AuthCheckingContext, token string) *authpublic.AuthenticatedUser {
	tokenUser, ok := context.Config.BearerToken.Tokens[token]
	if !ok {
		log.WithFields(log.Fields{
			"tokenPreview": previewToken(token),
		}).Debug("Bearer token not found in configured tokens")
		return nil
	}

	user := &authpublic.AuthenticatedUser{
		Username:      tokenUser.Username,
		UsergroupLine: tokenUser.Usergroup,
		Provider:      "bearer",
	}

	log.WithFields(log.Fields{
		"username":  user.Username,
		"usergroup": user.UsergroupLine,
		"provider":  user.Provider,
	}).Infof("Bearer token authentication successful")

	return user
}

// previewToken returns a preview of the token for logging (first 8 chars)
func previewToken(token string) string {
	if len(token) > 8 {
		return token[:8] + "..."
	}
	return token
}
