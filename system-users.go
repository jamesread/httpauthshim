package auth

import (
	authpublic "github.com/jamesread/httpauthshim/authpublic"
)

func UserGuest(cfg *authpublic.Config) *authpublic.AuthenticatedUser {
	ret := &authpublic.AuthenticatedUser{}
	ret.Username = "guest"
	ret.UsergroupLine = "guest"
	ret.Provider = "system"

	ret.BuildUserAcls(cfg)

	return ret
}

func UserFromSystem(cfg *authpublic.Config, username string) *authpublic.AuthenticatedUser {
	ret := &authpublic.AuthenticatedUser{
		Username:      username,
		UsergroupLine: "system",
		Provider:      "system",
	}

	ret.BuildUserAcls(cfg)

	return ret
}
