# Database Migration Notes

## New / Updated Tables

### kv_store (new)
```sql
CREATE TABLE IF NOT EXISTS kv_store (
    key_hash TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0
);
```

### users – new column
```sql
ALTER TABLE users ADD COLUMN webauthn_credentials_encrypted TEXT DEFAULT NULL;
```

### zt_sessions – new column
```sql
ALTER TABLE zt_sessions ADD COLUMN client_fingerprint_hash TEXT DEFAULT NULL;
```

## Full recommended CREATE statements (for fresh installs)

See the updated `Database.php` migrate() method in the main repository after applying the patch.
