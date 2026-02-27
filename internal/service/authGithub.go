package service

import (
	"fmt"
	"forum/internal/models"
	"time"

	"github.com/gofrs/uuid"
)

func (a *AuthService) CreateOrLoginByGithub(user_g models.GithubUserData) (string, time.Time, error) {
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
	user.Email = user_g.NodeID
	user.Username = user_g.Login[:6] + "(" + user_g.NodeID[:8] + ")"

	//check exists Email in db
	exist, err := a.storage.CheckUserByNameEmail(user.Email, user.Username)
	if err != nil {
		return "", time.Time{}, err
	}
	if exist {
		user2, err := a.storage.Auth.GetUserByEmail(user.Email)
		if err != nil {
			return "", time.Time{}, err
		}
		// if user2.Username != user.Username {
		// 	fmt.Println("Email already in use!")
		// 	return "", time.Time{}, err
		// }
		if err := a.storage.SaveToken(tokenStr, expired, user2.Username); err != nil {
			fmt.Println("github sign in can not save token")
			return "", time.Time{}, err
		}
		return tokenStr, expired, nil
	} else { //create new user if not exist
		err := a.storage.Auth.CreateUserGithub(user.Email, user.Username)
		if err != nil {
			return "", time.Time{}, err
		}
		if err := a.storage.SaveToken(tokenStr, expired, user.Username); err != nil {
			return "", time.Time{}, err
		}
		return tokenStr, expired, nil
	}
}
