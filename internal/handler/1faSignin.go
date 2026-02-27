package handler

import (
	"errors"
	"forum/internal/models"
	"forum/internal/storage"
	"net"
	"net/http"
	"time"
)

func (h *Handler) verifyPrimaryAuth(r *http.Request, username, password string) (string, time.Time, error) {
	rules := []Rule{
		{
			Key:    "rate:ip:login:" + clientIP(r.RemoteAddr),
			Limit:  10,
			Window: time.Minute,
		},
		{
			Key:    "rate:user:login:" + username,
			Limit:  5,
			Window: 10 * time.Minute,
		},
	}

	allowed, err := h.CheckAtomic(storage.RDB, rules)
	if err != nil {
		return "", time.Now(), errServiceUnavailable
	}
	if !allowed {
		return "", time.Now(), errTooManyAttempts
	}

	token, expired, err := h.Service.CheckUser(models.User{
		Username: username,
		Password: password,
	})
	return token, expired, err
}

func (h *Handler) renderSignInFormError(w http.ResponseWriter, message, username string) {
	info := models.InfoSign{
		Error:    message,
		Username: username,
	}

	if err := h.Temp.ExecuteTemplate(w, "signin.html", info); err != nil {
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

var (
	errServiceUnavailable = errors.New("service unavailable")
	errTooManyAttempts    = errors.New("too many attempts")
)

func clientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}
