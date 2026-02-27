package service

import (
	"errors"
	"forum/internal/models"
	"forum/internal/storage"
	"regexp"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Auth interface {
	CreateUser(user models.User) error
	CheckUser(user models.User) (string, time.Time, error)
	CreateSession(username string) (string, time.Time, error)
	GetTokenByUsername(username string) (string, time.Time, error)
	DeleteToken(token string) error
	DeleteTokenByUserID(userid int) error
	CreateOrLoginByGoogle(user_g models.GoogleLoginUserData) (string, time.Time, error)
	CreateOrLoginByGithub(user_g models.GithubUserData) (string, time.Time, error)

	SaveEmailCode(username string, codeHash string, expiresAt time.Time) (string, error)
	CheckEmailCode(username string, codeHash string) (bool, error)

	SaveCredentials(cred *models.WebAuthnCredential) error
	GetCredentials(userID int) ([]webauthn.Credential, error)
	HasWebAuthn(userID int) bool
	GetUserIDByCredentialID(credentialID []byte) (int, error)
	UpdateSignCount(credentialID []byte, signCount uint32) error
	DeleteAllCredentialsByUserID(userID int64) error
	GetUserByUsername(username string) (models.User, error)
}

type AuthService struct {
	storage *storage.Storage
}

func NewAuthService(storage *storage.Storage) *AuthService {
	return &AuthService{
		storage: storage,
	}
}

func (a *AuthService) CreateUser(user models.User) error {
	if err := validUser(user); err != nil {
		return err
	}

	uniq, err := a.storage.CheckUserByNameEmail(user.Email, user.Username)
	if err != nil {
		return err
	}
	if uniq {
		return errors.New(" Username or Email is already in used! ")
	}

	user.Password, err = generateHashPassword(user.Password)
	if err != nil {
		return err
	}

	return a.storage.Auth.CreateUser(user)
}

func (a *AuthService) CheckUser(user models.User) (string, time.Time, error) {
	password, err := a.storage.GetPasswordByUsername(user.Username)
	if err != nil {
		return "", time.Time{}, errors.New(" There is no user with that name <" + user.Username + "> ")
	}
	if err := compareHashAndPassword(password, user.Password); err != nil {
		return "", time.Time{}, err
	}

	return a.CreateSession(user.Username)
}

func (a *AuthService) CreateSession(username string) (string, time.Time, error) {
	token := uuid.NewGen()
	d, err := token.NewV4()
	if err != nil {
		return "", time.Time{}, err
	}
	expired := time.Now().Add(time.Hour * 12)
	if err := a.storage.SaveToken(d.String(), expired, username); err != nil {
		return "", time.Time{}, err
	}
	return d.String(), expired, nil
}

func generateHashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func compareHashAndPassword(hash, password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return models.ErrPasswordDoesNotMatch
	}
	return nil
}

func (a *AuthService) DeleteToken(token string) error {
	return a.storage.Auth.DeleteToken(token)
}

func (a *AuthService) DeleteTokenByUserID(userid int) error {
	return a.storage.Auth.DeleteTokenByUserID(userid)
}

func (a *AuthService) GetTokenByUsername(username string) (string, time.Time, error) {
	return a.storage.Auth.GetTokenByUsername(username)
}

func validUser(user models.User) error {
	for _, char := range user.Username {
		if char <= 32 || char >= 127 {
			return models.ErrInvalidUserName
		}
	}
	validEmail, err := regexp.MatchString(`[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`, user.Email)
	if err != nil {
		return err
	}
	if !validEmail {
		return models.ErrInvalidEmail
	}
	if len(user.Username) < 6 || len(user.Username) >= 36 {
		return models.ErrInvalidUserName
	}

	if !passIsValid(user.Password) {
		return models.ErrShortPassword
	}
	if user.Password != user.RepeatPassword {
		return models.ErrPasswordDoesNotMatch
	}
	return nil
}

func passIsValid(s string) bool {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(s) >= 8 || len(s) <= 20 {
		hasMinLen = true
	}
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

func (s *AuthService) SaveEmailCode(
	username string,
	codeHash string,
	expiresAt time.Time,
) (string, error) {
	return s.storage.SaveEmailCode(username, codeHash, expiresAt)
}

func (s *AuthService) CheckEmailCode(
	username string,
	codeHash string,
) (bool, error) {
	return s.storage.CheckEmailCode(username, codeHash)
}

func (s *AuthService) SaveCredentials(cred *models.WebAuthnCredential) error {
	return s.storage.Auth.SaveCredentials(cred)
}

func (s *AuthService) GetCredentials(userID int) ([]webauthn.Credential, error) {
	return s.storage.Auth.GetCredentials(userID)
}

func (s *AuthService) HasWebAuthn(userID int) bool {
	return s.storage.Auth.HasWebAuthn(userID)
}

func (s *AuthService) GetUserIDByCredentialID(credentialID []byte) (int, error) {
	return s.storage.Auth.GetUserIDByCredentialID(credentialID)
}

func (s *AuthService) UpdateSignCount(
	credentialID []byte,
	signCount uint32,
) error {
	return s.storage.Auth.UpdateSignCount(credentialID, signCount)
}

func (s *AuthService) DeleteAllCredentialsByUserID(userID int64) error {
	return s.storage.Auth.DeleteAllCredentialsByUserID(userID)
}

func (s *AuthService) GetUserByUsername(username string) (models.User, error) {
	return s.storage.Auth.GetUserByUsername(username)
}
