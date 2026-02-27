package models

import (
	"errors"
)

var (
	ErrCommentNotFound      = errors.New("The page does not exist or comment has been deleted")
	ErrPostNotFound         = errors.New("The page does not exist or post has been deleted")
	ErrUserNotFound         = errors.New("User does not exist or password incorrect")
	ErrInvalidUserName      = errors.New("Invalid username - your username should consist at least 6 characters")
	ErrInvalidEmail         = errors.New("Invalid email")
	ErrPasswordDoesNotMatch = errors.New("Password Does Not Match")
	ErrShortPassword        = errors.New("Incorrect password - your password should be a minimum of 8 characters and consist of at least:1 lower case letter, 1 upper case letter, 1 number, 1 special symbol")
)

type Error struct {
	Status     int
	StatusText string
	Message    string
	Back       string
}
