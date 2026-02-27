CREATE TABLE IF NOT EXISTS user (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT UNIQUE,
	username TEXT UNIQUE,
	password TEXT,
	session_token TEXT DEFAULT NULL,
	expiresAt DATETIME DEFAULT NULL,
	imageBack TEXT DEFAULT 'black.png',
	imageURL TEXT DEFAULT 'ava.jpg',
	rol TEXT DEFAULT 'user',
	bio TEXT DEFAULT 'hey i am new user',
	created_at DATE DEFAULT (datetime('now','localtime')),
    updated_at DATE DEFAULT (datetime('now','localtime')),
	email_code_hash TEXT,
	email_code_expires_at DATETIME,
	email_code_attempts INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_username
ON user(username);

INSERT INTO user (email,username,password) 
SELECT 'elnursccc@gmail.com','great_king','$2a$10$NtyegXYqaRIpCCA9fA.uguuypOqOQM34O7sqRdrlBMrmRFu5cdIKq'
WHERE NOT EXISTS (SELECT 1 FROM user WHERE id = 1);
UPDATE user SET rol = 'king' WHERE id= 1;
UPDATE user SET imageURL = 'king.png' WHERE id= 1;

INSERT INTO user (email,username,password) 
SELECT 'prince1@gmail.com','prince','$2a$10$NtyegXYqaRIpCCA9fA.uguuypOqOQM34O7sqRdrlBMrmRFu5cdIKq'
WHERE NOT EXISTS (SELECT 1 FROM user WHERE id = 2);
UPDATE user SET rol = 'moderator' WHERE id= 2;
UPDATE user SET imageURL = 'mdr.png' WHERE id= 2;

INSERT INTO user (email,username,password) 
SELECT 'queen1@gmail.com','great_queen','$2a$10$NtyegXYqaRIpCCA9fA.uguuypOqOQM34O7sqRdrlBMrmRFu5cdIKq'
WHERE NOT EXISTS (SELECT 1 FROM user WHERE id = 3);
UPDATE user SET rol = 'admin' WHERE id= 3;
UPDATE user SET imageURL = 'admin.png' WHERE id= 3;