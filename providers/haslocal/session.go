package haslocal

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	types "github.com/jamesread/httpauthshim/authpublic"
	"github.com/jamesread/httpauthshim/sessions"
	"github.com/jamesread/golure/pkg/redact"
	log "github.com/sirupsen/logrus"
)

func getLocalSessionCookie(r *http.Request, cfg *types.Config) (string, bool) {
	cookieName := cfg.GetLocalSessionCookieName()
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	if c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func CheckUserFromLocalSession(context *types.AuthCheckingContext) *types.AuthenticatedUser {
	u := &types.AuthenticatedUser{}

	sid, ok := getLocalSessionCookie(context.Request, context.Config)
	if !ok {
		return u
	}

	var sess *sessions.UserSession
	if context.Sessions != nil {
		sess = context.Sessions.GetSession("local", sid)
	} else {
		sess = sessions.GetUserSession("local", sid)
	}
	if sess == nil {
		log.WithFields(log.Fields{"sid": redact.RedactString(sid), "provider": "local"}).Warn("UserFromContext: stale local session")
		return u
	}

	cfgUser := context.Config.FindUserByUsername(sess.Username)
	if cfgUser == nil {
		usernameHash := sha256.Sum256([]byte(sess.Username))
		usernameHashStr := hex.EncodeToString(usernameHash[:])
		log.WithFields(log.Fields{"username_hash": usernameHashStr}).Warn("UserFromContext: local session user not in config")
		return u
	}

	u.Username = cfgUser.Username
	u.UsergroupLine = cfgUser.UsergroupLine
	u.Provider = "local"
	u.SID = sid
	return u
}
