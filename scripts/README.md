# Colony Daemon API Test Scripts

This directory contains scripts for testing the Colony Daemon REST API.

## example.sh

A comprehensive test script that demonstrates the JWT authentication system and tests both public and protected endpoints of the colony-daemon REST API.

### Features

- **JWT Authentication**: Demonstrates the new password-protected authentication system
- **Public vs Protected Endpoints**: Clearly shows which endpoints require authentication
- **Async Job Polling**: Tests the asynchronous job-based API endpoints
- **Real-time Progress**: Shows job progress and completion status
- **Error Handling**: Graceful handling of authentication failures and job errors

### Prerequisites

1. **colony-daemon running**: The daemon must be running on `localhost:3000`
2. **jq installed**: Required for JSON parsing (`sudo apt install jq` or `brew install jq`)
3. **Valid keystore password**: The script needs the correct keystore password

### Usage

#### Basic Usage (with default password)
```bash
./scripts/example.sh
```

#### Custom Password
```bash
KEYSTORE_PASSWORD=your_password ./scripts/example.sh
```

#### Custom Base URL
```bash
BASE_URL=http://localhost:8080 ./scripts/example.sh
```

### What the Script Tests

#### Public Endpoints (No Authentication Required)
- ✅ Health check (`/health`)
- ✅ Async cache refresh (`/api/v1/jobs/cache/refresh`)
- ✅ Async refresh pod references (`/api/v1/jobs/cache/refresh/{depth}`)
- ✅ Async search (`/api/v1/jobs/search`)
- ✅ Async get subject data (`/api/v1/jobs/search/subject/{subject}`)
- ✅ Job status checking (`/api/v1/jobs/{job_id}`)
- ✅ Job result retrieval (`/api/v1/jobs/{job_id}/result`)

#### Protected Endpoints (Authentication Required)
- 🔒 Add pod (`/api/v1/pods`)
- 🔒 Put subject data (`/api/v1/pods/{pod}/{subject}`)
- 🔒 Add pod reference (`/api/v1/pods/{pod}/pod_ref`)
- 🔒 Async upload all pods (`/api/v1/jobs/cache/upload`)
- 🔒 List my pods (`/api/v1/pods`)

### Authentication Flow

1. **Request JWT Token**: POST to `/auth/token` with keystore password
2. **Receive Token**: Get JWT token with 10-minute expiration
3. **Use Token**: Include `Authorization: Bearer <token>` header for protected endpoints
4. **Token Validation**: Server validates token and password verification flag

### Sample Output

```
🚀 Testing Colony Daemon Async REST API with JWT Authentication
================================================================
🔑 Using keystore password: pas***

📝 Getting JWT token...
✅ Token obtained: eyJ0eXAiOiJKV1QiLCJh...
⏰ Token expires in: 600 seconds

🏥 Testing health check (public endpoint)...
{
  "status": "healthy",
  "timestamp": "2025-06-22T00:00:00.000000000+00:00",
  "version": "0.1.0"
}

➕ Testing add pod (protected endpoint)...
{
  "address": "a140b2697c6dd781a2487ac1595ba77a779281898f84940e3664244fafda7e55a73d8aba0b361ab750979b47c38cf80c",
  "name": "test-pod-1750550416",
  "timestamp": "2025-06-22T00:00:17.055399422+00:00"
}

✅ All async API tests completed!
```

### Troubleshooting

#### Authentication Failed
```bash
❌ Failed to get JWT token
Response:

💡 Tip: Make sure the colony-daemon is running and the keystore password is correct.
   You can set the password with: export KEYSTORE_PASSWORD='your_password'
```

**Solutions:**
- Verify colony-daemon is running: `curl http://localhost:3000/health`
- Check the correct keystore password
- Ensure the daemon was started with the expected password

#### jq Not Found
```bash
❌ Error: jq is required but not installed.
   Please install jq: https://stedolan.github.io/jq/download/
```

**Solutions:**
- Ubuntu/Debian: `sudo apt install jq`
- macOS: `brew install jq`
- Or download from: https://stedolan.github.io/jq/download/

### Environment Variables

- `KEYSTORE_PASSWORD`: The keystore password (default: "password")
- `BASE_URL`: The daemon base URL (default: "http://localhost:3000")

### Security Notes

- The script uses the actual keystore password for authentication
- Tokens expire after 10 minutes for security
- Protected endpoints require password-verified tokens
- The legacy endpoint (`/auth/token/legacy`) creates tokens without password verification that cannot access protected resources
