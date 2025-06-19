# 🏛️ Colony Utils

A collection of utilities for interacting with the [colonylib](https://github.com/zettawatt/colonylib) metadata framework for the [Autonomi](https://autonomi.com) decentralized network.

## 📦 Components

This repository contains two main components that work together to provide a complete solution for managing pods and metadata on the Autonomi network:

### 🚀 [colony-daemon](colony-daemon) - REST API Server
A high-performance server that implements the colonylib public APIs as REST endpoints.

**Key Features:**
- 🔧 Creates and manages colonylib PodManager instances
- 🌐 Provides comprehensive REST API for all colonylib operations
- 🔐 JWT-based authentication system
- ⚡ Asynchronous job processing with real-time status tracking
- 🗄️ Configurable data storage and keystore management
- 🌍 Multi-network support (local, alpha, main)

### 💻 [colony-cli](colony-cli) - Command Line Interface
A user-friendly CLI tool for interacting with the colony-daemon.

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

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zettawatt/colony-utils.git
   cd colony-utils
   ```

2. **Build the project:**
   ```bash
   cargo build --release
   ```

### Running the Daemon

Start the colony-daemon server:

```bash
# Basic usage (connects to main Autonomi network on port 3000)
./target/release/colony-daemon

# Custom configuration
./target/release/colony-daemon \
  --port 8080 \
  --listen 0.0.0.0 \
  --network alpha \
  --data /path/to/data \
  --pass pass:mypassword
```

### Using the CLI

Once the daemon is running, use the CLI to interact with it:

```bash
# List all pods
./target/release/colony-cli pods

# Create a new pod
./target/release/colony-cli add pod "my-new-pod"

# Search for content
./target/release/colony-cli search text "example query" --limit 10

# Refresh cache
./target/release/colony-cli refresh

# Upload all pods
./target/release/colony-cli upload
```

## 📖 Detailed Usage

### Colony Daemon Configuration

The `colony-daemon` supports various configuration options:

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
- `RUST_LOG` - Set logging level (e.g., `debug`, `info`, `warn`, `error`)

#### Example Configurations

**Development Setup (Local Network):**
```bash
colony-daemon --network local --port 3000 --listen 127.0.0.1
```

**Production Setup (Main Network):**
```bash
colony-daemon --port 3000 --listen 0.0.0.0
```

**Alpha Testing:**
```bash
colony-daemon --network alpha
```

### Colony CLI Usage

The `colony-cli` provides a comprehensive interface to the daemon:

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
colony-cli refresh

# Refresh with specific depth
colony-cli refresh --depth 2

# Upload all pods
colony-cli upload

# Upload specific pod
colony-cli upload <pod-address>
```

**Search Operations:**
```bash
# Text search
colony-cli search text "search term" --limit 50

# SPARQL query
colony-cli search sparql "SELECT * WHERE { GRAPH { ?s ?p ?o }}"

# Search by type - list all files of the type MediaObject
colony-cli search type "http://schema.org/MediaObject" --limit 20

# Search by predicate - list all files by name
colony-cli search predicate "http://schema.org/name" --limit 10

# Search by subject. Returns everything about an address on the network.
colony-cli search subject "c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59"
```

**Pod Management:**
```bash
# List all pods
colony-cli pods

# Create new pod
colony-cli add pod "my-pod-name"

# Add pod reference
colony-cli add ref <pod-address> <reference>

# Remove pod reference
colony-cli rm ref <pod-address> <reference>

# Store data in pod
colony-cli put <pod-address> <subject> <JSON-LD data string>
```

#### Environment Variables

- `COLONYCLI_SERVER` - Default server URL
- `COLONYCLI_PORT` - Default server port

#### Examples

**Basic Workflow:**
```bash
# Refresh all pods from the network to the local cache
colony-cli refresh --depth 3

# Create a new pod and give it a name
colony-cli add pod "music" # returns the pod address e.g. 8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e

# Write metadata in JSON-LD format using [schema.org vocabulary](https://schema.org/) about a
# particular subject (i.e. a file on the network)
colony-cli put 8cca45fa078bc86f0861e23781632c2c3bfbd2012e259cf7c2b1f5025f3789ceb0910dd8e1943a700778f5f969a4261e c859818c623ce4fc0899c2ab43061b19caa0b0598eec35ef309dbe50c8af8d59 '{\
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
colony-cli upload

# Now we can search for the data we just uploaded, either by a simple text query
colony-cli search text "beg blag and steal" --limit 5

# Or by raw SPARQL query for more complex queries
colony-cli search sparql '\
  PREFIX schema: <http://schema.org/>\
  SELECT DISTINCT ?ant WHERE { GRAPH {\
    ?ant schema:name "BegBlag.mp3" .\
  }}'
```

## 🏗️ Architecture

### System Overview

```
┌─────────────────┐    HTTP/REST    ┌─────────────────┐
│   colony-cli    │ ──────────────► │  colony-daemon  │
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
- `POST /auth/token` - Get JWT token
- `GET /health` - Health check

**Asynchronous Operations:**
- `POST /api/v1/jobs/cache/refresh` - Start cache refresh
- `POST /api/v1/jobs/cache/refresh/{depth}` - Refresh with depth
- `POST /api/v1/jobs/cache/upload` - Upload all pods
- `POST /api/v1/jobs/cache/upload/{address}` - Upload specific pod
- `POST /api/v1/jobs/search` - Start search job
- `POST /api/v1/jobs/search/subject/{subject}` - Search by subject
- `GET /api/v1/jobs/{job_id}` - Get job status
- `GET /api/v1/jobs/{job_id}/result` - Get job result

**Synchronous Operations:**
- `GET /api/v1/pods` - List pods
- `POST /api/v1/pods` - Create pod
- `PUT /api/v1/pods/{pod}/{subject}` - Store subject data
- `POST /api/v1/pods/{pod}/pod_ref` - Add pod reference
- `DELETE /api/v1/pods/{pod}/pod_ref` - Remove pod reference

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

### Project Structure

```
colony-utils/
├── colony-daemon/          # REST API server
│   ├── src/
│   │   └── main.rs         # Main daemon implementation
│   ├── scripts/            # Testing and example scripts
│   └── Cargo.toml          # Daemon dependencies
├── colony-cli/             # Command line interface
│   ├── src/
│   │   └── main.rs         # CLI implementation
│   └── Cargo.toml          # CLI dependencies
├── Cargo.toml              # Workspace configuration
└── README.md               # This file
```

## 🐛 Troubleshooting

### Common Issues

**Connection Refused:**
```bash
# Ensure daemon is running
ps aux | grep colony-daemon

# Check if port is available
netstat -tlnp | grep :3000
```

**Authentication Errors:**
```bash
# Verify daemon is accessible
curl http://localhost:3000/health

# Get a fresh token
curl -X POST http://localhost:3000/auth/token
```

**Network Issues:**
```bash
# Check network connectivity
colony-daemon --network local  # Use local testnet

# Verify Ethereum wallet
# Ensure private key is valid and has sufficient funds
```

### Logging

Enable debug logging for troubleshooting:

```bash
# Daemon with debug logging
RUST_LOG=debug colony-daemon

# Specific module logging
RUST_LOG=colony_daemon=debug,colonylib=info colony-daemon
```

## 📄 License

This project is licensed under the GPL-3.0-only License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Autonomi Network**: [autonomi.com](https://autonomi.com)
- **colonylib**: [github.com/zettawatt/colonylib](https://github.com/zettawatt/colonylib)
