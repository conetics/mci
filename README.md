# MCI - Model Control Interface

MCI is a REST API server for managing definitions and modules. It stores metadata in PostgreSQL and persists binary artifacts, configuration, and secrets in S3-compatible object storage.

Key capabilities:

- Install definitions and modules from remote registries or local files
- Digest-verified (SHA-256) artifact uploads
- JSON Schema validation for configuration and secrets
- Incremental updates via JSON Patch (RFC 6902)
- Optional KMS server-side encryption for secrets at rest
- Automatic upgrade from source with digest comparison
- TLS support via rustls

## Architecture

```
Routes -> Handlers -> Services -> PostgreSQL / S3
```

- **HTTP layer** -- Axum with optional rustls TLS, graceful shutdown on SIGINT
- **Database** -- PostgreSQL via Diesel ORM with r2d2 connection pooling
- **Object storage** -- Any S3-compatible backend (tested with SeaweedFS and MinIO)
- **Async runtime** -- Tokio

### Data Model

**Definitions** represent versioned artifacts identified by a namespace ID, type, name, description, SHA-256 digest, and an optional source URL.

**Modules** follow the same structure but are typed by category: `language`, `sandbox`, `interceptor`, `proxy`, or `hook`.

Both support associated configuration and secrets, each validated against a co-located JSON Schema.

### S3 Bucket Layout

| Bucket | Contents |
|---|---|
| `definitions` | Definition binary artifacts |
| `modules` | Module WASM binaries |
| `definitions-configuration` | Configuration JSON and JSON Schema per definition |
| `modules-configuration` | Configuration JSON and JSON Schema per module |
| `definitions-secrets` | Secrets JSON and JSON Schema per definition |
| `modules-secrets` | Secrets JSON and JSON Schema per module |

## Configuration

All settings are loaded from environment variables prefixed with `MCI_`.

| Variable | Default | Required | Description |
|---|---|---|---|
| `MCI_ADDRESS` | `0.0.0.0:7687` | No | Listen address and port |
| `MCI_DATABASE_URL` | -- | Yes | PostgreSQL connection string |
| `MCI_S3_URL` | -- | Yes | S3-compatible endpoint URL |
| `MCI_S3_REGION` | `us-east-1` | No | S3 region |
| `MCI_S3_ACCESS_KEY` | `none` | No | S3 access key |
| `MCI_S3_SECRET_KEY` | `none` | No | S3 secret key |
| `MCI_S3_KMS_KEY_ID` | -- | No | KMS key ID for encrypting secrets at rest |
| `MCI_LOG_LEVEL` | -- | No | Tracing log level filter (e.g. `info`, `debug`) |
| `MCI_KEY_PATH` | -- | No | Path to TLS private key PEM file |
| `MCI_CERT_PATH` | -- | No | Path to TLS certificate PEM file |

When both `MCI_KEY_PATH` and `MCI_CERT_PATH` are provided, the server starts with HTTPS. Otherwise it falls back to plain HTTP.

When `MCI_S3_KMS_KEY_ID` is not set, secrets are stored without server-side encryption.

## Getting Started

### Docker Compose

The quickest way to run MCI with all dependencies:

```sh
docker compose up
```

This starts PostgreSQL, SeaweedFS (S3), runs database migrations, and launches the MCI server on port 7687.

### Nix Development Shell

If you use Nix with flakes:

```sh
nix develop
```

This provides Rust (with clippy, rust-src, rust-analyzer), OpenSSL, libpq, diesel-cli, cargo-watch, and docker-compose.

### Manual Setup

Requirements:

- Rust 1.83+
- PostgreSQL
- An S3-compatible object store (MinIO, SeaweedFS, AWS S3, etc.)
- diesel-cli (`cargo install diesel_cli --no-default-features --features postgres`)

Run database migrations:

```sh
diesel migration run --database-url <your-database-url>
```

Build and run:

```sh
export MCI_DATABASE_URL="postgres://mci:mci@localhost/mci"
export MCI_S3_URL="http://localhost:8333"
cargo run
```

### TLS Certificates

To generate self-signed certificates for local development:

```sh
./scripts/generate_certs.sh
```

This creates `certs/key.pem` and `certs/cert.pem`. Point `MCI_KEY_PATH` and `MCI_CERT_PATH` to these files to enable HTTPS.

## API Reference

### Definitions

| Method | Path | Description |
|---|---|---|
| GET | `/definitions` | List definitions (supports filtering, sorting, pagination) |
| POST | `/definitions` | Create a definition from a payload with a file URL |
| POST | `/definitions/install` | Install a definition from a remote registry source URL |
| GET | `/definitions/:id` | Get a definition by ID |
| PATCH | `/definitions/:id` | Partially update a definition's metadata |
| DELETE | `/definitions/:id` | Delete a definition and its S3 artifacts |
| POST | `/definitions/:id/upgrade` | Re-fetch and update a definition from its source URL |
| GET | `/definitions/:id/configuration` | Get configuration JSON with schema validation result |
| PUT | `/definitions/:id/configuration` | Replace configuration (validated against schema) |
| PATCH | `/definitions/:id/configuration` | Apply a JSON Patch to configuration |
| GET | `/definitions/:id/configuration/schema` | Get configuration JSON Schema |
| PATCH | `/definitions/:id/secrets` | Apply a JSON Patch to secrets |
| GET | `/definitions/:id/secrets/schema` | Get secrets JSON Schema |

### Modules

| Method | Path | Description |
|---|---|---|
| GET | `/modules` | List modules (supports filtering, sorting, pagination) |
| POST | `/modules` | Create a module from a payload with a file URL |
| POST | `/modules/install` | Install a module from a remote registry source URL |
| GET | `/modules/:id` | Get a module by ID |
| PATCH | `/modules/:id` | Partially update a module's metadata |
| DELETE | `/modules/:id` | Delete a module and its S3 artifacts |
| POST | `/modules/:id/upgrade` | Re-fetch and update a module from its source URL |
| GET | `/modules/:id/configuration` | Get configuration JSON with schema validation result |
| PUT | `/modules/:id/configuration` | Replace configuration (validated against schema) |
| PATCH | `/modules/:id/configuration` | Apply a JSON Patch to configuration |
| GET | `/modules/:id/configuration/schema` | Get configuration JSON Schema |
| PATCH | `/modules/:id/secrets` | Apply a JSON Patch to secrets |
| GET | `/modules/:id/secrets/schema` | Get secrets JSON Schema |

### List Query Parameters

Both `/definitions` and `/modules` list endpoints accept:

| Parameter | Type | Description |
|---|---|---|
| `search` | string | Search across id, name, and description (case-insensitive) |
| `enabled` | boolean | Filter by enabled status |
| `type` | string | Filter by type |
| `limit` | integer | Maximum number of results |
| `offset` | integer | Number of results to skip |
| `sort_by` | `id`, `name`, `type` | Field to sort by |
| `sort_order` | `asc`, `desc` | Sort direction |

### Error Response Format

All errors are returned as JSON:

```json
{
  "error": {
    "type": "not_found",
    "message": "Definition with id 'example' not found"
  }
}
```

## Testing

### Unit Tests

Unit tests live alongside their source in `_tests.rs` companion files:

```sh
cargo test --lib
```

### Integration Tests

Integration tests use testcontainers to spin up real PostgreSQL and MinIO instances. They are located in the `tests/` directory:

```sh
cargo test --test api_handlers
cargo test --test definition_service
cargo test --test module_service
cargo test --test configuration_service
cargo test --test s3_put_stream
cargo test --test s3_delete_objects
```

Docker must be available for the testcontainers to start.

## Project Structure

```
src/
  main.rs              -- Entry point, server startup, TLS/graceful shutdown
  config.rs            -- Environment-based configuration
  db.rs                -- Diesel/r2d2 connection pool setup
  errors.rs            -- Centralized error types mapped to HTTP responses
  http.rs              -- Reqwest HTTP client factory
  models.rs            -- Diesel ORM models with validation
  s3.rs                -- S3 client factory
  schema.rs            -- Auto-generated Diesel schema
  api/
    routes.rs          -- Axum route definitions
    handlers.rs        -- Request handlers
  services/
    definitions_services.rs    -- Definition CRUD and registry install
    modules_services.rs        -- Module CRUD and registry install
    configuration_services.rs  -- Configuration get/put/patch with schema validation
    secrets_services.rs        -- Secrets patch with optional KMS encryption
  utils/
    json_utils.rs      -- JSON Patch application
    regex_utils.rs     -- Validation regex patterns
    s3_utils.rs        -- S3 upload and batch delete
    source_utils.rs    -- Source URL/file path parsing
    stream_utils.rs    -- HTTP and filesystem streaming
migrations/            -- Diesel database migrations
tests/                 -- Integration tests with testcontainers
```
