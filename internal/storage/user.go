package storage

import (
	"database/sql"
	"fmt"
	"log"

	"forum/internal/models"
)

type User interface {
	GetUserByToken(token string) (models.User, error)
	GetUserById(id int) (models.User, error)
	GetAllUser(your_id int) ([]models.User, error)
	CheckUserByNameEmail(email, username string) (bool, error)
	CheckUserByName(username string) (bool, error)
	CheckUserByEmail(email string) (bool, error)
	UpdateUserName(id int, username string) error
	GetUserByEmail(email string) (models.User, error)
}

type UserStorage struct {
	db *sql.DB
}

func NewUserStorage(db *sql.DB) *UserStorage {
	return &UserStorage{
		db: db,
	}
}

func (u *UserStorage) GetUserByToken(token string) (models.User, error) {
	query := `SELECT 
			id, 
			email, 
			username, 
			imageBack,
			imageURL,
			rol,
			bio,
			expiresAt
		FROM user 
		WHERE session_token = $1;`
	row := u.db.QueryRow(query, token)
	var user models.User
	if err := row.Scan(&user.Id, &user.Email, &user.Username, &user.ImageBack, &user.ImageURL, &user.Rol, &user.Bio, &user.ExpiresAt); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (u *UserStorage) GetUserById(id int) (models.User, error) {
	query := `SELECT 
			id, 
			email, 
			username, 
			imageBack,
			imageURL,
			rol,
			bio,
			expiresAt
		FROM user 
		WHERE id = $1;`
	row := u.db.QueryRow(query, id)
	var user models.User
	if err := row.Scan(&user.Id, &user.Email, &user.Username, &user.ImageBack, &user.ImageURL, &user.Rol, &user.Bio, &user.ExpiresAt); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (u *UserStorage) GetAllUser(your_id int) ([]models.User, error) {
	query := `SELECT id, email, username,  
                imageBack, imageURL, rol, bio
            FROM user 
            WHERE id != ? 
            ORDER BY created_at ASC`

	rows, err := u.db.Query(query, your_id)
	if err != nil {
		return nil, fmt.Errorf("unable to query users:%s", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.Id, &user.Email, &user.Username, &user.ImageBack, &user.ImageURL, &user.Rol, &user.Bio)
		if err != nil {
			return nil, fmt.Errorf("unable to scan user row%s", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over user rows%s", err)
	}
	return users, nil
}

func (u *UserStorage) CheckUserByNameEmail(email, username string) (bool, error) {

	query := "SELECT EXISTS(SELECT 1 FROM user WHERE email = ? OR username = ?) AS UE_exists;"

	row := u.db.QueryRow(query, email, username)

	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (u *UserStorage) CheckUserByName(username string) (bool, error) {

	query := "SELECT EXISTS(SELECT 1 FROM user WHERE username = ?) AS UE_exists;"

	row := u.db.QueryRow(query, username)

	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (u *UserStorage) CheckUserByEmail(email string) (bool, error) {

	query := "SELECT EXISTS(SELECT 1 FROM user WHERE email = ? ) AS UE_exists;"

	row := u.db.QueryRow(query, email)

	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (u *UserStorage) UpdateUserName(id int, username string) error {
	query := `UPDATE user SET username = $1 WHERE id= $2;`
	if _, err := u.db.Exec(query, username, id); err != nil {
		return err
	}
	return nil
}

func (u *UserStorage) GetUserByEmail(email string) (models.User, error) {
	query := `SELECT 
			id, 
			username, 
			imageBack,
			imageURL,
			rol,
			bio,
			expiresAt
		FROM user 
		WHERE email = ?;`
	row := u.db.QueryRow(query, email)
	var user models.User
	if err := row.Scan(&user.Id, &user.Username, &user.ImageBack, &user.ImageURL, &user.Rol, &user.Bio, &user.ExpiresAt); err != nil {
		log.Printf("GetUserByEmail(%q) error: %v\n", email, err)
		return models.User{}, err
	}
	return user, nil
}
