

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    credential_id  BLOB NOT NULL UNIQUE,
    public_key     BLOB NOT NULL,
    sign_count     INTEGER NOT NULL,
    is_passkey     BOOLEAN DEFAULT 0,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at   DATETIME DEFAULT(datetime('now','localtime')),
    backup_eligible BOOLEAN DEFAULT 0,
    backup_state BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES user(id)
);