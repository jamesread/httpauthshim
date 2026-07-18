package hastrustedheaders

import (
	"net"
	"net/http"
	"strings"

	authpublic "github.com/jamesread/httpauthshim/authpublic"
)

func CheckUserFromHeaders(context *authpublic.AuthCheckingContext) *authpublic.AuthenticatedUser {
	if !isTrustedHeadersEnabled(context) {
		return nil
	}
	if !isRequestFromTrustedProxy(context) {
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

func isRequestFromTrustedProxy(context *authpublic.AuthCheckingContext) bool {
	if context.Request == nil {
		return false
	}
	return remoteAddrInCIDRs(context.Request.RemoteAddr, context.Config.HttpHeader.TrustedProxyCIDRs)
}

func remoteAddrInCIDRs(remoteAddr string, cidrs []string) bool {
	host := remoteAddrHost(remoteAddr)
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		if ipInCIDR(ip, cidr) {
			return true
		}
	}
	return false
}

func remoteAddrHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	// RemoteAddr without port (rare)
	return strings.TrimSpace(remoteAddr)
}

func ipInCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	return network.Contains(ip)
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
