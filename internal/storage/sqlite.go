package storage

import (
	"database/sql"
	"forum/internal/models"
	"forum/internal/server"
	"io/ioutil"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

func InitDB(config server.Config) *sql.DB {
	db, err := sql.Open(config.DB.Driver, config.DB.Dsn)
	if err != nil {
		models.ErrLog.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		models.ErrLog.Fatal(err)
	}
	migrations := []string{"userTable.sql",
		"postTable.sql",
		"categoriesTable.sql",
		"commentTable.sql",
		"reactionCommentTable.sql",
		"reactionPostTable.sql",
		"notificationTable.sql",
		"communication.sql",
		"action.sql",
		"userWebAuth.sql",
		"userAuth.sql"}
	for _, migrationFile := range migrations {
		content, err := ioutil.ReadFile(filepath.Join("migrations", migrationFile))
		if err != nil {
			models.ErrLog.Fatal(err)
		}
		if _, err = db.Exec(string(content)); err != nil {
			models.ErrLog.Fatal(err)
		}
	}
	models.InfoLog.Println("Connection to the database was successful")
	return db
}
