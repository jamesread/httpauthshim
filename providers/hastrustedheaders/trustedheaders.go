package hastrustedheaders

import (
	"net/http"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
)

func CheckUserFromHeaders(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	if !isTrustedHeadersEnabled(context) {
		return nil
	}

	u := readUserFromTrustedHeaders(context)
	if u.Username == "" && u.UsergroupLine == "" {
		return nil
	}

	return u
}

func isTrustedHeadersEnabled(context *authpublic.AuthCheckingContext) bool {
	return context.Config != nil && context.Config.HttpHeader.Enabled
}

func readUserFromTrustedHeaders(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	u := &authpublic.AuthenticatedUser{
		Provider: "trusted-header",
	}

	headerCfg := context.Config.HttpHeader
	if headerCfg.Username != "" {
		u.Username = getHeaderKeyOrEmpty(context.Request.Header, headerCfg.Username)
	}

	if headerCfg.UserGroup != "" {
		u.UsergroupLine = getHeaderKeyOrEmpty(context.Request.Header, headerCfg.UserGroup)
	}

	return u
}

func getHeaderKeyOrEmpty(headers http.Header, key string) string {
	values := headers.Values(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}
