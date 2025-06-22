# Colony Daemon Authentication System

This document describes the secure authentication system implemented for colony-daemon and colony-cli.

## Overview

The authentication system requires users to provide the keystore password to obtain JWT tokens. This ensures that only users who know the keystore password can access protected endpoints and perform operations that modify the keystore.

## Security Features

### 1. Password-Protected JWT Tokens
- JWT tokens now include a `password_verified` claim
- Tokens can only be created by providing the correct keystore password
- All protected endpoints require tokens with `password_verified: true`

### 2. Keystore Password Integration
- The keystore password provided at daemon startup is used for JWT token creation
- All `KeyStore::to_file()` operations now use the actual keystore password instead of hardcoded strings
- Password is securely stored in the daemon's AppState

### 3. Token Caching in CLI
- colony-cli caches valid tokens locally in `~/.colony-cli/token.json`
- Tokens are automatically validated for expiration
- New tokens are requested only when needed

## API Endpoints

### Authentication Endpoints

#### `POST /auth/token` (Password-Protected)
Creates a JWT token with password verification.

**Request:**
```json
{
  "password": "your_keystore_password"
}
```

**Response (Success):**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 600,
  "token_type": "Bearer"
}
```

**Response (Unauthorized):**
```
HTTP 401 Unauthorized
```

#### `POST /auth/token/legacy` (Legacy - No Password)
Creates a JWT token without password verification (for backward compatibility).
**Note:** Tokens from this endpoint cannot access protected resources.

### Protected Endpoints
All API endpoints under `/api/v1/` require:
1. Valid JWT token in Authorization header: `Bearer <token>`
2. Token must have `password_verified: true`

## CLI Usage

### Automatic Authentication
The colony-cli automatically handles authentication:

```bash
# First time - will prompt for password
colony-cli pods

# Subsequent calls use cached token
colony-cli search text "example"

# When token expires, will prompt for password again
colony-cli add pod "new-pod"
```

### Token Caching
- Tokens are cached in `~/.colony-cli/token.json` (or whatever `dirs::home_dir()` resolves to for non-Unix systems)
- Cache includes expiration time for automatic validation
- Invalid/expired tokens are automatically refreshed

## Implementation Details

### JWT Claims Structure
```rust
struct Claims {
    sub: String,           // Subject (always "colony-daemon")
    exp: usize,           // Expiration timestamp
    iat: usize,           // Issued at timestamp
    password_verified: bool, // Password verification flag
}
```

### Authentication Middleware
The `auth_middleware` function:
1. Extracts JWT token from Authorization header
2. Validates token signature and expiration
3. Checks `password_verified` claim
4. Rejects requests with `password_verified: false`

### PodManager Integration
All PodManager operations that call `KeyStore::to_file()` now:
1. Receive the keystore password as a parameter
2. Use the actual password instead of hardcoded strings
3. Ensure keystore consistency across operations

## Security Considerations

### Password Handling
- Passwords are never logged or stored in plaintext
- CLI prompts use secure input (hidden characters)
- Passwords are only transmitted over HTTPS in production

### Token Security
- Tokens expire after 10 minutes
- Tokens are signed with the keystore password
- Legacy tokens without password verification are rejected

## Testing

Run the authentication system tests:

```bash
# Unit tests
cd colony-daemon
cargo test test_password_protected_token_creation
cargo test test_token_validation_logic

# Integration test
cd /home/system/colony-utils
./test_auth_flow.sh
```
