package storage

import (
	"database/sql"
	"forum/internal/models"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Auth interface {
	CreateUser(user models.User) error
	GetUserByUsername(username string) (models.User, error)
	SaveToken(token string, expired time.Time, username string) error
	GetTokenByUsername(
		username string,
	) (string, time.Time, error)
	GetPasswordByUsername(username string) (string, error)
	GetUserByEmail(email string) (models.User, error)
	DeleteToken(token string) error
	DeleteTokenByUserID(userid int) error
	CreateUserGoogle(email, username string) error
	CreateUserGithub(email, username string) error

	SaveEmailCode(username, codeHash string, expiresAt time.Time) (string, error)
	CheckEmailCode(username, codeHash string) (bool, error)

	SaveCredentials(cred *models.WebAuthnCredential) error
	GetCredentials(userID int) ([]webauthn.Credential, error)
	HasWebAuthn(userID int) bool
	GetUserIDByCredentialID(credentialID []byte) (int, error)
	UpdateSignCount(credentialID []byte, signCount uint32) error
	DeleteAllCredentialsByUserID(userID int64) error
}

type AuthStorage struct {
	db *sql.DB
}

func NewAuthStorage(db *sql.DB) *AuthStorage {
	return &AuthStorage{
		db: db,
	}
}

func (a *AuthStorage) CreateUser(user models.User) error {
	query := `INSERT INTO user(email, username, password) VALUES ($1, $2, $3);`
	_, err := a.db.Exec(query, user.Email, user.Username, user.Password)
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthStorage) GetUserByUsername(username string) (models.User, error) {
	query := `SELECT id, email, username FROM user WHERE username = $1;`
	row := a.db.QueryRow(query, username)
	var user models.User
	if err := row.Scan(&user.Id, &user.Email, &user.Username); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (a *AuthStorage) GetUserByEmail(email string) (models.User, error) {
	query := `SELECT id, email, username FROM user WHERE email = $1;`
	row := a.db.QueryRow(query, email)
	var user models.User
	if err := row.Scan(&user.Id, &user.Email, &user.Username); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (a *AuthStorage) SaveToken(token string, expired time.Time, username string) error {
	query := `UPDATE user SET session_token = $1, expiresAt = $2 WHERE username = $3;`
	if _, err := a.db.Exec(query, token, expired, username); err != nil {
		return err
	}
	return nil
}

func (a *AuthStorage) GetTokenByUsername(
	username string,
) (string, time.Time, error) {

	query := `
		SELECT session_token, expiresAt
		FROM "user"
		WHERE username = $1;
	`

	var token sql.NullString
	var expiresAt sql.NullTime

	err := a.db.QueryRow(query, username).
		Scan(&token, &expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}

	if !token.Valid || !expiresAt.Valid {
		return "", time.Time{}, sql.ErrNoRows
	}

	return token.String, expiresAt.Time, nil
}

func (a *AuthStorage) GetPasswordByUsername(username string) (string, error) {
	query := `SELECT password FROM user WHERE username = $1;`
	row := a.db.QueryRow(query, username)
	var password string
	if err := row.Scan(&password); err != nil {
		return password, err
	}
	return password, nil
}

func (a *AuthStorage) DeleteToken(token string) error {
	query := `UPDATE user SET session_token = NULL, expiresAt = NULL WHERE session_token = $1`
	if _, err := a.db.Exec(query, token); err != nil {
		return err
	}
	return nil
}

func (a *AuthStorage) DeleteTokenByUserID(userId int) error {
	query := `UPDATE user SET session_token = NULL, expiresAt = NULL WHERE id = $1`
	if _, err := a.db.Exec(query, userId); err != nil {
		return err
	}
	return nil
}

func (a *AuthStorage) SaveEmailCode(
	username string,
	codeHash string,
	expiresAt time.Time,
) (string, error) {

	var email string

	query := `
		UPDATE "user"
		SET email_code_hash = $1,
		    email_code_expires_at = $2,
		    email_code_attempts = 0
		WHERE username = $3
		RETURNING email;
	`

	err := a.db.QueryRow(query, codeHash, expiresAt, username).Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", err
		}
		return "", err
	}

	return email, nil
}

func (a *AuthStorage) CheckEmailCode(
	username string,
	codeHash string,
) (bool, error) {
	var storedHash sql.NullString
	var expiresAt sql.NullTime
	var attempts int

	query := `
		SELECT email_code_hash,
		       email_code_expires_at,
		       email_code_attempts
		FROM "user"
		WHERE username = $1;
	`

	err := a.db.QueryRow(query, username).
		Scan(&storedHash, &expiresAt, &attempts)
	if err != nil {
		return false, err
	}

	// нет активного кода
	if !storedHash.Valid || !expiresAt.Valid {
		return false, nil
	}

	// истёк
	if time.Now().After(expiresAt.Time) {
		_, _ = a.db.Exec(`
			UPDATE "user"
			SET email_code_hash = NULL,
			    email_code_expires_at = NULL,
			    email_code_attempts = 0
			WHERE username = $1;
		`, username)
		return false, nil
	}

	// превышены попытки
	if attempts >= 5 {
		return false, nil
	}

	// неверный код
	if storedHash.String != codeHash {
		_, _ = a.db.Exec(`
			UPDATE "user"
			SET email_code_attempts = email_code_attempts + 1
			WHERE username = $1;
		`, username)
		return false, nil
	}

	// успех — очищаем код
	_, err = a.db.Exec(`
		UPDATE "user"
		SET email_code_hash = NULL,
		    email_code_expires_at = NULL,
		    email_code_attempts = 0
		WHERE username = $1;
	`, username)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (a *AuthStorage) GetUserIDByCredentialID(credentialID []byte) (int, error) {
	const q = `
		SELECT user_id
		FROM webauthn_credentials
		WHERE credential_id = ?
		LIMIT 1
	`

	var userID int
	err := a.db.QueryRow(q, credentialID).Scan(&userID)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (a *AuthStorage) UpdateSignCount(
	credentialID []byte,
	signCount uint32,
) error {
	_, err := a.db.Exec(`
		UPDATE webauthn_credentials
		SET sign_count = ?, last_used_at = datetime('now')
		WHERE credential_id = ?
	`, signCount, credentialID)

	return err
}
