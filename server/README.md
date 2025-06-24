# OpenADP Server

This module provides server-side functionality for running OpenADP servers that participate in distributed cryptographic operations.

## Packages

### `server`
Core server business logic:
- Secret registration and recovery
- Cryptographic operations (OPRF evaluation)
- Request validation and processing
- Session management with Noise protocol
- Monitoring and health checks

### `database`
Database operations and management:
- SQLite-based storage
- Share storage and retrieval
- Guess count tracking
- Backup management

### `middleware`
HTTP middleware components:
- Authentication middleware
- Request logging and monitoring
- Error handling

### `auth`
Authentication and authorization:
- Auth code management
- User authentication
- Session validation

## Usage

### Running a Server

```go
import (
    "github.com/openadp/server/server"
    "github.com/openadp/server/database"
)

// Initialize database
db, err := database.NewDatabase("server.db")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

// Register a secret share
err = server.RegisterSecret(db, "user123", "device456", "backup789", 
    "authcode", 1, 1, shareData, 10, 0)
if err != nil {
    log.Fatal(err)
}

// Recover a secret share
response, err := server.RecoverSecret(db, "user123", "device456", "backup789", 
    point, 0)
if err != nil {
    log.Fatal(err)
}
```

### Database Operations

```go
import "github.com/openadp/server/database"

// Create database
db, err := database.NewDatabase("server.db")
if err != nil {
    log.Fatal(err)
}

// Insert a record
err = db.Insert("user123", "device456", "backup789", "authcode", 
    1, 1, shareData, 0, 10, 0)

// Lookup a record
record, err := db.Lookup("user123", "device456", "backup789")
```

## Dependencies

- `github.com/openadp/common` - Shared cryptographic primitives
- `github.com/gorilla/mux` - HTTP routing
- `modernc.org/sqlite` - SQLite database driver

## Server Configuration

Servers can be configured with:
- Database path
- Noise protocol keys for secure communication
- Monitoring and logging settings
- Rate limiting and security policies 