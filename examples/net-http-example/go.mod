module net-http-example

go 1.25.0

require github.com/jamesread/httpauthshim v0.0.0

require (
	github.com/alexedwards/argon2id v1.0.0 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/jamesread/golure v0.0.0-20250919212919-976d085a100c // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)

replace github.com/jamesread/httpauthshim => ../..
