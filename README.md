# 🏛️ Colony Utils

A collection of utilities for interacting with the [colonylib](https://github.com/zettawatt/colonylib) metadata framework for the [Autonomi](https://autonomi.com) decentralized network.

## 📦 Components

This repository contains a single Rust crate called `colony-utils` that provides two binary executables for managing pods and metadata on the Autonomi network:

### 🚀 `colonyd` - REST API Server
A high-performance server that implements the colonylib public APIs as REST endpoints.

**Key Features:**
- 🔧 Creates and manages colonylib PodManager instances
- 🌐 Provides comprehensive REST API for all colonylib operations
- 🔐 JWT-based authentication system
- ⚡ Asynchronous job processing with real-time status tracking
- 🗄️ Configurable data storage and keystore management
- 🌍 Multi-network support (local, alpha, main)

### 💻 `colony` - Command Line Interface
A user-friendly CLI tool for interacting with the colonyd daemon.

**Key Features:**
- 🎨 Colorful and intuitive interface with sub-command help
- 📊 Real-time progress indicators for long-running operations
- 🔍 Comprehensive search capabilities (text, SPARQL, type-based)
- 📦 Pod management (create, list, upload, refresh)
- 🔗 Reference management (add/remove pod references)
- 📝 Subject data operations
- 🌐 Environment variable support for configuration

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+ installed
- Access to an Autonomi network (local testnet, alpha, or main)
- Ethereum wallet private key (for network upload operations)

### Installation

There are 3 options: directly install binaries (linux only), install from crates.io, or build from source:

#### From binaries

1. **Download the latest release:**
   ```bash
   # Linux (Desktop)
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colonyd-x86_64-unknown-linux-musl
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colony-x86_64-unknown-linux-musl

   # macOS (Intel CPU - Older Macs)
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colonyd-x86_64-apple-darwin
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colony-x86_64-apple-darwin

   # macOS (Apple Silicon - Newer Macs)
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colonyd-aarch64-apple-darwin
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colony-aarch64-apple-darwin

   # Windows
   # NOTE: Windows will complain about this binary being 'unsafe'. Microsoft wants developers to pay for a certificate.
   # You can ignore this warning.
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colonyd-x86_64-pc-windows-msvc.exe -outfile colonyd
   wget https://github.com/zettawatt/colony-utils/releases/latest/download/colony-x86_64-pc-windows-msvc.exe -outfile colony
   ```

2. **Make executable and move to PATH (Linux/macOS):**
   ```bash
   chmod +x colonyd-* colony-*
   sudo mv colonyd-* /usr/local/bin/colonyd
   sudo mv colony-* /usr/local/bin/colony
   ```

#### From crates.io

1. **Install using the cargo command:**
```bash
cargo install colony-utils
```

#### From Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zettawatt/colony-utils.git
   cd colony-utils
   ```

2. **Build the project:**
   ```bash
   cargo build --release
   ```

3. **Move the binaries to a directory in your PATH:**
   ```bash
   sudo mv target/release/colonyd /usr/local/bin/
   sudo mv target/release/colony /usr/local/bin/
   ```

### Running the Daemon

Start the colonyd server:

```bash
# Basic usage (connects to main Autonomi network on port 3000)
colonyd

# Custom configuration
colonyd \
  --port 8080 \
  --listen 0.0.0.0 \
  --network alpha \
  --data /path/to/data \
  --pass pass:mypassword
```

### Using the CLI

Once the daemon is running, use the CLI to interact with it:

```bash
# Search for content (public - no auth required)
colony search text "example query" --limit 10

# Refresh cache (public - no auth required)
colony refresh

# List all pods (protected - requires auth)
colony pods

# Create a new pod (protected - requires auth)
colony add pod "my-new-pod"

# Remove a pod (protected - requires auth)
colony rm pod <pod-address>

# Rename a pod (protected - requires auth)
colony rename pod <pod-address> "new-name"

# Upload all pods (protected - requires auth)
colony upload
```

**Note**: The CLI automatically handles JWT authentication for protected operations. You'll be prompted for your keystore password when needed.

## 📖 Detailed Usage

### Colony Daemon Configuration

The `colonyd` daemon supports various configuration options:

#### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--port` | `-p` | Port to listen on | `3000` |
| `--listen` | `-l` | IP address to bind to | `127.0.0.1` |
| `--network` | `-n` | Autonomi network (`local`, `alpha`, `main`) | `main` |
| `--data` | `-d` | Path to data directory | `~/.local/share/colony` |
| `--pass` | | Password specification (see below) | Interactive prompt |

#### Password Specification

The `--pass` argument supports multiple formats:
- `pass:<password>` - Direct password
- `file:<path>` - Read password from file (NOT YET IMPLEMENTED)
- Omit for interactive prompt

#### Environment Variables

The daemon respects standard logging environment variables:
- `RUST_LOG` - Set logging level for all (e.g., `debug`, `info`, `warn`, `error`) or can set to a specific level of debug logging based on what you're doing. This is a good verbose default:
```bash
export RUST_LOG="colony_daemon=debug,colonylib=debug,tower_http=debug,axum=debug,autonomi=error"
```

#### Example Configurations

**Development Setup (Local Network):**
```bash
colonyd --network local --port 3000 --listen 127.0.0.1
```

**Production Setup (Main Network):**
```bash
colonyd --port 3000 --listen 0.0.0.0
```

**Alpha Testing:**
```bash
colonyd --network alpha
```

### Colony CLI Usage

The `colony` CLI provides a comprehensive interface to the daemon:

#### Global Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--server` | `-s` | Server URL | `http://localhost` or `$COLONYCLI_SERVER` |
| `--port` | `-p` | Server port | `3000` or `$COLONYCLI_PORT` |
| `--no-color` | | Disable colored output | Colors enabled |

#### Commands Overview

**Cache Operations:**
```bash
# Refresh cache
colony refresh

# Refresh with specific depth
colony refresh --depth 2

# Upload all pods
colony upload

# Upload specific pod
colony upload <pod-address>
```

**Search Operations:**
```bash
# Text search
colony search text "search term" --limit 50

# SPARQL query
colony search sparql "SELECT * WHERE { GRAPH { ?s ?p ?o }}"

# Search by type - list all files of the type MediaObject
colony search type "http://schema.org/MediaObject" --limit 20

# Search by predicate - list all files by name
colony search predicate "http://schema.org/name" --limit 10

# Search by subject. Returns everything about an address on the network.
colony search subject "c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59"
```

**Pod Management:**
```bash
# List all pods
colony pods

# Create new pod
colony add pod "my-pod-name"

# Remove pod
colony rm pod <pod-address>

# Rename pod
colony rename pod <pod-address> <new-name>

# Add pod reference
colony add ref <pod-address> <reference>

# Remove pod reference
colony rm ref <pod-address> <reference>

# Store data in pod
colony put <pod-address> <subject> <JSON-LD data string>
```

#### Environment Variables

- `COLONYCLI_SERVER` - Default server URL
- `COLONYCLI_PORT` - Default server port
- `COLONY_PASSWORD` - Keystore password (avoids interactive prompts for protected operations)

#### Examples

**Basic Workflow:**
```bash
# Refresh all pods from the network to the local cache
colony refresh --depth 3

# Create a new pod and give it a name
colony add pod "music" # returns the pod address e.g. 8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e

# Write metadata in JSON-LD format using [schema.org vocabulary](https://schema.org/) about a
# particular subject (i.e. a file on the network)
colony put 8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59 '{\
        "@context": {"schema": "http://schema.org/"},\
        "@type": "schema:MediaObject",\
        "@id": "ant://c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59",\
        "schema:name": "BegBlag.mp3",\
        "schema:description": "Beg Blag and Steal",\
        "schema:contentSize": "3MB"\
      }'

# Write as much metadata as you want into the pod or multiple pods
# about any subject you want, regardless of whether you uploaded the data

# Then upload all pods to the Autonomi network
colony upload

# Now we can search for the data we just uploaded, either by a simple text query
colony search text "beg blag and steal" --limit 5

# Or by raw SPARQL query for more complex queries
colony search sparql '\
  PREFIX schema: <http://schema.org/>\
  SELECT DISTINCT ?ant WHERE { GRAPH {\
    ?ant schema:name "BegBlag.mp3" .\
  }}'
```

## 🏗️ Architecture

### System Overview

```
┌─────────────────┐    HTTP/REST    ┌─────────────────┐
│     colony      │ ──────────────► │     colonyd     │
│                 │                 │                 │
│ • CLI Interface │                 │ • REST API      │
│ • Progress Bars │                 │ • JWT Auth      │
│ • Colored Output│                 │ • Job Queue     │
└─────────────────┘                 └─────────────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │   colonylib     │
                                    │                 │
                                    │ • PodManager    │
                                    │ • DataStore     │
                                    │ • KeyStore      │
                                    └─────────────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │ Autonomi Network│
                                    │                 │
                                    │ • Decentralized │
                                    │ • Immutable     │
                                    │ • Secure        │
                                    └─────────────────┘
```

### API Endpoints

The daemon exposes the following REST endpoints:

**Authentication:**
- `POST /auth/token` - Get JWT token (requires keystore password)
- `GET /health` - Health check (public)

**Asynchronous Operations (Public - No Auth Required):**
- `POST /api/v1/jobs/cache/refresh` - Start cache refresh
- `POST /api/v1/jobs/cache/refresh/{depth}` - Refresh with depth
- `POST /api/v1/jobs/search` - Start search job
- `POST /api/v1/jobs/search/subject/{subject}` - Search by subject
- `GET /api/v1/jobs/{job_id}` - Get job status
- `GET /api/v1/jobs/{job_id}/result` - Get job result

**Asynchronous Operations (Protected - Auth Required):**
- `POST /api/v1/jobs/cache/upload` - Upload all pods 🔒
- `POST /api/v1/jobs/cache/upload/{address}` - Upload specific pod 🔒

**Synchronous Operations (Protected - Auth Required):**
- `GET /api/v1/pods` - List pods 🔒
- `POST /api/v1/pods` - Create pod 🔒
- `DELETE /api/v1/pods/{pod}` - Remove pod 🔒
- `POST /api/v1/pods/{pod}` - Rename pod 🔒
- `PUT /api/v1/pods/{pod}/{subject}` - Store subject data 🔒
- `POST /api/v1/pods/{pod}/pod_ref` - Add pod reference 🔒
- `DELETE /api/v1/pods/{pod}/pod_ref` - Remove pod reference 🔒

### 🔐 Authentication & Security

The colony-daemon implements a JWT-based authentication system to protect sensitive operations:

#### Authentication Flow

1. **Get JWT Token**: Send a POST request to `/auth/token` with your keystore password
2. **Use Token**: Include the token in the `Authorization: Bearer <token>` header
3. **Token Expiration**: Tokens expire after 10 minutes for security

#### Example Authentication

```bash
# Get a JWT token
TOKEN=$(curl -s -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"password": "your_keystore_password"}' | jq -r '.token')

# Use the token for protected endpoints
curl -X POST http://localhost:3000/api/v1/pods \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-new-pod"}'
```

#### Endpoint Security

- **🔓 Public Endpoints**: No authentication required
  - Health check, search operations, job status/results, cache refresh
- **🔒 Protected Endpoints**: Require valid JWT token with password verification
  - Pod creation/management, data storage, upload operations, listing pods



## 🔧 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/zettawatt/colony-utils.git
cd colony-utils

# Build all components
cargo build

# Build with optimizations
cargo build --release
```

### Testing the API

The repository includes a comprehensive test script that demonstrates all API endpoints:

```bash
# Run the example script (requires daemon to be running)
./scripts/example.sh

# Or with custom password
KEYSTORE_PASSWORD=your_password ./scripts/example.sh
```

The script tests both public and protected endpoints, showing proper JWT authentication flow.

### Project Structure

```
colony-utils/
├── src/
│   └── bin/
│       ├── colonyd.rs      # REST API server binary
│       └── colony.rs       # CLI binary
├── scripts/                # Testing and example scripts
├── Cargo.toml              # Single crate configuration
├── ASYNC_JOBS.md           # Documentation for async job system
├── AUTHENTICATION.md       # Authentication documentation
└── README.md               # This file
```

## 🐛 Troubleshooting

### Common Issues

**Connection Refused:**
```bash
# Ensure daemon is running
ps aux | grep colonyd

# Check if port is available
netstat -tlnp | grep :3000
```

**Authentication Errors:**
```bash
# Verify daemon is accessible
curl http://localhost:3000/health

# Test authentication with correct password
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"password": "your_keystore_password"}'

# Check if you're using the correct keystore password
# The daemon will return 401 Unauthorized for incorrect passwords


```

**Network Issues:**
```bash
# Check network connectivity
colonyd --network local  # Use local testnet

# Verify Ethereum wallet
# Ensure private key is valid and has sufficient funds
```

### Logging

Enable debug logging for troubleshooting:

```bash
# Daemon with debug logging
RUST_LOG=debug colonyd

# Specific module logging
RUST_LOG=colony_daemon=debug,colonylib=info colonyd
```

## 📄 License

This project is licensed under the GPL-3.0-only License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Autonomi Network**: [autonomi.com](https://autonomi.com)
- **colonylib**: [github.com/zettawatt/colonylib](https://github.com/zettawatt/colonylib)
