package service

import (
	"fmt"
	"forum/internal/models"
	"time"

	"github.com/gofrs/uuid"
)

func (a *AuthService) CreateOrLoginByGoogle(user_g models.GoogleLoginUserData) (string, time.Time, error) {
	var user models.User

	//create new token for google user
	token := uuid.NewGen()
	d, err := token.NewV4()
	if err != nil {
		return "", time.Time{}, err
	}
	tokenStr := d.String()
	expired := time.Now().Add(time.Hour * 12)
	//use google email
	user.Email = user_g.Email
	user.Username = user_g.Name[:6] + "(" + tokenStr[:8] + ")"

	//check exists Email in db
	exist, err := a.storage.CheckUserByEmail(user.Email)
	if err != nil {
		return "", time.Time{}, err
	}
	if exist {
		user2, err := a.storage.Auth.GetUserByEmail(user.Email)
		if err != nil {
			return "", time.Time{}, err
		}
		// if user2.Username[:6] != user.Username[:6] {
		// 	fmt.Println("Email already in use!")
		// 	return "", time.Time{}, err
		// }
		if err := a.storage.SaveToken(d.String(), expired, user2.Username); err != nil {
			fmt.Println("google sign in can not save token")
			return "", time.Time{}, err
		}
		return d.String(), expired, nil
	} else { //create new user if not exist
		err := a.storage.Auth.CreateUserGoogle(user.Email, user.Username)
		if err != nil {
			return "", time.Time{}, err
		}
		if err := a.storage.SaveToken(d.String(), expired, user.Username); err != nil {
			return "", time.Time{}, err
		}
		return d.String(), expired, nil
	}
}
