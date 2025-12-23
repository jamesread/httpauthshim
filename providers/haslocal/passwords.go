package haslocal

import (
	"runtime"

	"github.com/alexedwards/argon2id"
	"github.com/jamesread/httpauthshim/authpublic"
	log "github.com/sirupsen/logrus"
)

var defaultParams = argon2id.Params{
	Memory:      64 * 1024,
	Iterations:  4,
	Parallelism: uint8(runtime.NumCPU()),
	SaltLength:  16,
	KeyLength:   32,
}

// dummyHash is a valid Argon2id hash that will always fail comparison
// but takes similar time to verify, preventing timing attacks
// Generated at package initialization to ensure it uses the same parameters
var dummyHash string

func init() {
	// Generate a dummy hash at initialization time
	// This ensures it uses the same Argon2id parameters as real password hashes
	hash, err := argon2id.CreateHash("dummy-password-for-timing-attack-prevention", &defaultParams)
	if err != nil {
		// Fallback to a hardcoded hash if generation fails (shouldn't happen)
		// This is a valid Argon2id hash format that will always fail comparison
		dummyHash = "$argon2id$v=19$m=65536,t=4,p=1$dGVzdHNhbHRlc3Q$dGVzdGhhc2h0ZXN0aGFzaHRlc3RoYXNo"
		log.Errorf("Failed to generate dummy hash, using fallback: %v", err)
	} else {
		dummyHash = hash
	}
}

func CreateHash(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, &defaultParams)

	if err != nil {
		log.Errorf("Error creating hash: %v", err)
		return "", err
	}

	return hash, nil
}

func comparePasswordAndHash(password, hash string) bool {
	match, err := argon2id.ComparePasswordAndHash(password, hash)

	if err != nil {
		log.Errorf("Error comparing password and hash: %v", err)
		return false
	}

	return match
}

// CheckUserPassword checks if the provided username and password are valid.
// To prevent timing attacks, this function always performs a password hash
// comparison, even when the user doesn't exist, using a dummy hash.
func CheckUserPassword(cfg *authpublic.Config, username, password string) bool {
	var foundUser *authpublic.LocalUser
	var userHash string

	// Find the user first
	for _, user := range cfg.LocalUsers.Users {
		if user.Username == username {
			foundUser = user
			userHash = user.Password
			break
		}
	}

	// Always perform hash comparison to prevent timing attacks
	// If user not found, use dummy hash that will always fail but takes similar time
	if foundUser == nil {
		// Perform dummy hash comparison to maintain constant-time behavior
		comparePasswordAndHash(password, dummyHash)
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("Failed to check password for user, as username was not found")
		return false
	}

	// User exists, perform actual password comparison
	match := comparePasswordAndHash(password, userHash)

	if match {
		return true
	} else {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("Password does not match for user")
		return false
	}
}
