-- DROP TABLE IF EXISTS notification;

CREATE TABLE IF NOT EXISTS notification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INT,
    to_user_id INT,
    post_id INT NULL,
	comment_id INT NULL,
    message TEXT,
    activity INT DEFAULT 1,
    created_at DATE,
    FOREIGN KEY (post_id) REFERENCES post(id) ON DELETE CASCADE,
    FOREIGN KEY (from_user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (to_user_id) REFERENCES user(id) ON DELETE CASCADE,
    FOREIGN KEY (comment_id) REFERENCES comment(id) ON DELETE CASCADE
);
