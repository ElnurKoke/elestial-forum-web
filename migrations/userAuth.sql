CREATE TABLE IF NOT EXISTS risk_assessments (
    user_id INTEGER NOT NULL,
    risk_level TEXT DEFAULT 'YELLOW' CHECK (risk_level IN ('GREEN','YELLOW','RED')),
    reason TEXT,
    primary_geo TEXT DEFAULT 'Kazakhstan',
    primary_ip TEXT,
    primary_device TEXT,
    primary_online_time DATETIME DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_assessments_user_id
ON risk_assessments(user_id);

CREATE TABLE IF NOT EXISTS user_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT,
    geo TEXT,
    device TEXT,
    status BOOLEAN,
    reason TEXT,
    event_time DATETIME DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

INSERT INTO risk_assessments (
    user_id,
    risk_level,
    primary_geo,
    primary_ip,
    primary_device,
    primary_online_time
)
SELECT
    1,
    'GREEN',
    'Kazakhstan',
    'unknown',
    'unknown',
    datetime('now','localtime')
WHERE NOT EXISTS (SELECT 1 FROM risk_assessments WHERE user_id = 1);

INSERT INTO risk_assessments (
    user_id,
    risk_level,
    primary_geo,
    primary_ip,
    primary_device,
    primary_online_time
)
SELECT
    2,
    'GREEN',
    'Kazakhstan',
    'unknown',
    'unknown',
    datetime('now','localtime')
WHERE NOT EXISTS (SELECT 1 FROM risk_assessments WHERE user_id = 2);

INSERT INTO risk_assessments (
    user_id,
    risk_level,
    primary_geo,
    primary_ip,
    primary_device,
    primary_online_time
)
SELECT
    3,
    'GREEN',
    'Kazakhstan',
    'unknown',
    'unknown',
    datetime('now','localtime')
WHERE NOT EXISTS (SELECT 1 FROM risk_assessments WHERE user_id = 3);
