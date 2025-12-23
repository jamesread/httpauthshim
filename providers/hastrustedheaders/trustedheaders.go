package hastrustedheaders

import (
	"net/http"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
)

//gocyclo:ignore
func CheckUserFromHeaders(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	u := &authpublic.AuthenticatedUser{}

	if context.Config.HttpHeader.Username != "" {
		u.Username = getHeaderKeyOrEmpty(context.Request.Header, context.Config.HttpHeader.Username)
	}

	if context.Config.HttpHeader.UserGroup != "" {
		u.UsergroupLine = getHeaderKeyOrEmpty(context.Request.Header, context.Config.HttpHeader.UserGroup)
	}

	if prov := getHeaderKeyOrEmpty(context.Request.Header, "provider"); prov != "" {
		u.Provider = prov
	}

	if u.Username == "" && u.UsergroupLine == "" {
		return nil
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
