CREATE TABLE IF NOT EXISTS post (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	author_id INT,
	title TEXT,
	description TEXT,
	imageURL TEXT,
	likes INT DEFAULT 0,
	dislikes INT DEFAULT 0,
	category TEXT,
	status TEXT DEFAULT 'waiting',
	created_at DATE DEFAULT (datetime('now','localtime')),
	FOREIGN KEY (author_id) REFERENCES user(id)
);