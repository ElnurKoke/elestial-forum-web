package service

import (
	"errors"
	"forum/internal/models"
	"forum/internal/storage"
	"strings"
)

type User interface {
	GetUserByToken(token string) (models.User, error)
	GetUserById(id int) (models.User, error)
	GetAllUser(your_id int) ([]models.User, error)
	UpdateUserName(id int, username string) error
	GetUserByEmail(email string) (models.User, error)
}

type UserService struct {
	storage *storage.Storage
}

func NewUserService(storage *storage.Storage) *UserService {
	return &UserService{
		storage: storage,
	}
}

func (u *UserService) GetUserByToken(token string) (models.User, error) {
	return u.storage.User.GetUserByToken(token)
}
func (u *UserService) GetUserById(id int) (models.User, error) {
	return u.storage.User.GetUserById(id)
}
func (u *UserService) GetAllUser(your_id int) ([]models.User, error) {
	return u.storage.User.GetAllUser(your_id)
}

func (u *UserService) UpdateUserName(id int, username string) error {
	if username == "" {
		return errors.New(" username field not found (empty username)")
	}
	if len(username) > 35 {
		return errors.New(" username should be shorter than 36 symbols")
	}
	check, err := u.storage.User.CheckUserByNameEmail(username, username)
	if err != nil {
		return errors.New(" error func CheckUserByNameEmail")
	}
	if check {
		return errors.New(" Sorry, but you cant use this Username, try other username")
	}
	return u.storage.User.UpdateUserName(id, username)
}

func (u *UserService) GetUserByEmail(email string) (models.User, error) {
	email = strings.TrimSpace(email)
	return u.storage.User.GetUserByEmail(email)
}
