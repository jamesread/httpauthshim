# net/http Example

This example demonstrates how to use the `httpauthshim` library with a standard Go `net/http` server.

## Features Demonstrated

- **AuthShimContext**: Creating and using the main authentication context
- **Multiple Authentication Methods**:
  - Trusted HTTP headers (X-Username, X-User-Group)
  - JWT tokens (from headers or cookies)
  - Local password-based sessions
  - OAuth2 (GitHub) - optional
- **Session Management**: Registering and managing user sessions
- **Access Control Lists (ACLs)**: Admin-only route protection
- **Guest Users**: Handling unauthenticated requests

## Running the Example

1. **Install dependencies**:
   ```bash
   go mod init net-http-example
   go get github.com/jamesread/httpauthshim
   ```

2. **Set up OAuth2 (optional)**:
   ```bash
   export GITHUB_CLIENT_ID="your-client-id"
   export GITHUB_CLIENT_SECRET="your-client-secret"
   ```

3. **Run the server**:
   ```bash
   go run main.go
   ```

4. **Access the application**:
   - Visit http://localhost:8080
   - Try the protected endpoints:
     - `/api/protected` - Requires authentication
     - `/api/admin` - Requires admin ACL
     - `/api/login` - POST with username/password

## Testing Authentication Methods

### 1. Trusted Headers
```bash
curl -H "X-Username: admin" -H "X-User-Group: admin" http://localhost:8080/api/protected
```

### 2. JWT Token (Header)
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:8080/api/protected
```

### 3. Local Password Login
```bash
# Login
curl -X POST http://localhost:8080/api/login \
  -d "username=admin" \
  -d "password=admin123" \
  -c cookies.txt

# Use session cookie
curl http://localhost:8080/api/protected -b cookies.txt
```

### 4. OAuth2 (GitHub)
Visit http://localhost:8080/oauth/login?provider=github in your browser.

## Code Structure

- **main.go**: Complete example server with:
  - Configuration setup
  - AuthShimContext initialization
  - Multiple route handlers demonstrating different authentication scenarios
  - Session management
  - ACL-based authorization

## Key Concepts

1. **AuthShimContext**: The main entry point that encapsulates Config and Sessions
2. **AuthFromHttpReq()**: Authenticates a request and returns an AuthenticatedUser
3. **IsGuest()**: Check if user is unauthenticated
4. **ACLs**: Access Control Lists for fine-grained authorization
5. **Session Management**: RegisterUserSession, GetUserSession, DeleteUserSession

## Notes

- In production, always use HTTPS and set Secure cookies
- Generate session IDs using `crypto/rand`, not simple strings
- Use `haslocal.CreateHash()` to generate password hashes
- Configure OAuth2 providers properly with valid credentials
- Sessions are persisted to disk automatically
