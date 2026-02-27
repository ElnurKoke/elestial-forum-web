package storage

import (
	"forum/internal/models"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestCreateUser_PreventsSQLInjection_WithParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	st := &AuthStorage{db: db}

	maliciousUsername := "attacker'); DROP TABLE \"user\"; --"
	user := models.User{
		Email:    "victim@example.com",
		Username: maliciousUsername,
		Password: "p@ssword",
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO user(email, username, password) VALUES ($1, $2, $3);`)).
		WithArgs(user.Email, user.Username, user.Password).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = st.CreateUser(user)
	require.NoError(t, err)

	err = mock.ExpectationsWereMet()
	require.NoError(t, err)
}
