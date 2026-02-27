package handler

import (
	"encoding/json"
	"fmt"
	"forum/internal/models"
	"net/http"
	"net/url"
	"time"
)

func (h *Handler) googleAuth(w http.ResponseWriter, r *http.Request) {
	googleOAuthConfig := h.Config.OAuth.Google
	url := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&prompt=select_account",
		googleOAuthConfig.AuthURL, googleOAuthConfig.ClientID, googleOAuthConfig.RedirectURL, "email profile")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) googleAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	pathUrl := "/"

	state := r.FormValue("state")
	if state != "" {
		pathUrl = state
	}
	if code == "" {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	googleOAuthConfig := h.Config.OAuth.Google
	tokenRes, err := GetGoogleOauthToken(code, googleOAuthConfig)
	if err != nil {
		h.ErrorPage(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	google_user, err := GetGoogleUser(tokenRes.Access_token, tokenRes.Id_token, googleOAuthConfig.UserInfoURL)
	if err != nil {
		h.ErrorPage(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}

	now := time.Now()

	user_data := models.GoogleLoginUserData{
		Name:      google_user.Name,
		Email:     google_user.Email,
		Password:  "",
		Photo:     google_user.Picture,
		Provider:  "Google",
		Role:      "user",
		Verified:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	models.InfoLog.Printf("\n        Name:  %s\n        Email: %s\n        Photo: %s\n        Status:%s\n",
		user_data.Name, user_data.Email, user_data.Photo, "OAuth Google")
	token, expired, err := h.Service.Auth.CreateOrLoginByGoogle(user_data)
	if err != nil {
		info := models.InfoSign{
			Error:    err.Error(),
			Username: user_data.Name,
			Password: user_data.Password,
		}
		if err := h.Temp.ExecuteTemplate(w, "signin.html", info); err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token,
		Path:    "/",
		Expires: expired,
	})
	http.Redirect(w, r, pathUrl, http.StatusSeeOther)
}

type GoogleUserResult struct {
	Id             string
	Email          string
	Verified_email bool
	Name           string
	Given_name     string
	Family_name    string
	Picture        string
	Locale         string
}

func GetGoogleUser(access_token string, id_token string, userInfoURL string) (*GoogleUserResult, error) {
	url := fmt.Sprintf("%s?alt=json&access_token=%s", userInfoURL, access_token)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", id_token))

	client := http.Client{Timeout: time.Second * 30}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not retrieve user: %s", res.Status)
	}

	var userInfo GoogleUserResult
	if err := json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

type GoogleOauthToken struct {
	Access_token string
	Id_token     string
}

func GetGoogleOauthToken(code string, config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}) (*GoogleOauthToken, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)
	data.Set("redirect_uri", config.RedirectURL)

	res, err := http.PostForm(config.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not retrieve token: %s", res.Status)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	if err := json.NewDecoder(res.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &GoogleOauthToken{
		Access_token: tokenResp.AccessToken,
		Id_token:     tokenResp.IDToken,
	}, nil
}
