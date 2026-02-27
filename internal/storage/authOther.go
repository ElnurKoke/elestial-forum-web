package storage

import (
	"forum/internal/models"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
)

func (a *AuthStorage) CreateUserGoogle(email, username string) error {
	query := `INSERT INTO user(email, username, password) VALUES ($1, $2, $3);`
	_, err := a.db.Exec(query, email, username, "google")
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthStorage) CreateUserGithub(email, username string) error {
	query := `INSERT INTO user(email, username, password) VALUES ($1, $2, $3);`
	_, err := a.db.Exec(query, email, username, "github")
	if err != nil {
		return err
	}
	return nil
}

func (a *AuthStorage) SaveCredentials(cred *models.WebAuthnCredential) error {
	const query = `
	INSERT INTO webauthn_credentials
	(user_id, credential_id, public_key, sign_count, is_passkey )
	VALUES (?, ?, ?, ?, ?)
	`

	_, err := a.db.Exec(
		query,
		cred.UserID,
		cred.CredentialID,
		cred.PublicKey,
		cred.SignCount,
		cred.IsPasskey,
		// cred.BackupEligible,
		// cred.BackupState,
	)

	return err
}

func (a *AuthStorage) GetCredentials(userID int) ([]webauthn.Credential, error) {
	const query = `
	SELECT credential_id, public_key, sign_count
	FROM webauthn_credentials
	WHERE user_id = ?
	`

	rows, err := a.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []webauthn.Credential

	for rows.Next() {
		var (
			credID    []byte
			publicKey []byte
			signCount uint32
			// backupEligible bool
			// backupState    bool
		)

		if err := rows.Scan(&credID, &publicKey, &signCount); err != nil {
			return nil, err
		}

		creds = append(creds, webauthn.Credential{
			ID:        credID,
			PublicKey: publicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: signCount,
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: true,
				BackupState:    true,
			},
		})
	}

	return creds, rows.Err()
}

func (a *AuthStorage) HasWebAuthn(userID int) bool {
	var count int
	_ = a.db.QueryRow(`
		SELECT COUNT(1)
		FROM webauthn_credentials
		WHERE user_id = ?
	`, userID).Scan(&count)

	return count > 0
}

func (r *AuthStorage) DeleteAllCredentialsByUserID(userID int64) error {
	res, err := r.db.Exec(`
        DELETE FROM webauthn_credentials
        WHERE user_id = ?
    `, userID)
	if err != nil {
		return err
	}

	// необязательно, но полезно для логов
	rows, _ := res.RowsAffected()
	log.Printf("Deleted %d WebAuthn credentials for user %d", rows, userID)

	return nil
}
