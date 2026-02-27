package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"forum/internal/models"
	"io/ioutil"
	"log"
	"net/http"
)

func (h *Handler) githubLogin(w http.ResponseWriter, r *http.Request) {
	githubOAuthConfig := h.Config.OAuth.Github
	redirectURL := fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s",
		githubOAuthConfig.AuthURL,
		githubOAuthConfig.ClientID,
		githubOAuthConfig.RedirectURL)

	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
}

func (h *Handler) githubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	githubOAuthConfig := h.Config.OAuth.Github
	githubAccessToken := getGithubAccessToken(code, githubOAuthConfig.ClientID, githubOAuthConfig.ClientSecret, githubOAuthConfig.TokenURL)

	githubData := getGithubData(githubAccessToken, githubOAuthConfig.UserInfoURL)
	if githubData == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	var user_data models.GithubUserData
	if err := json.Unmarshal([]byte(githubData), &user_data); err != nil {
		log.Panic("JSON parse error:", err)
	}
	if len(user_data.NodeID) < 1 {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	models.InfoLog.Printf("\n        Login: %s\n        Nodel: %s\n        ID:    %d\n        Status:%s\n",
		user_data.Login, user_data.NodeID, user_data.ID, "OAuth Github")
	token, expired, err := h.Service.Auth.CreateOrLoginByGithub(user_data)
	if err != nil {
		info := models.InfoSign{
			Error:    err.Error(),
			Username: user_data.Login,
			Password: user_data.NodeID,
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func getGithubAccessToken(code, clientID, clientSecret, tokenURL string) string {
	requestBodyMap := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	}
	requestJSON, _ := json.Marshal(requestBodyMap)

	req, reqerr := http.NewRequest(
		"POST",
		tokenURL,
		bytes.NewBuffer(requestJSON),
	)
	if reqerr != nil {
		log.Panic("Request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	type githubAccessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}

	var ghresp githubAccessTokenResponse
	json.Unmarshal(respbody, &ghresp)

	return ghresp.AccessToken
}

func getGithubData(accessToken, userInfoURL string) string {
	req, reqerr := http.NewRequest(
		"GET",
		userInfoURL,
		nil,
	)
	if reqerr != nil {
		log.Panic("API Request creation failed")
	}

	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	return string(respbody)
}
