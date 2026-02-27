package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"forum/internal/models"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"time"
)

func generateEmailCode() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func sendEmailCode(to, code string, smtpConfig struct {
	From     string
	Password string
	Host     string
	Port     string
}) error {
	if smtpConfig.From == "" || smtpConfig.Password == "" || smtpConfig.Host == "" || smtpConfig.Port == "" {
		return fmt.Errorf("smtp config is not fully specified")
	}
	from := smtpConfig.From
	password := smtpConfig.Password
	host := smtpConfig.Host
	addr := host + ":" + smtpConfig.Port

	auth := smtp.PlainAuth("", from, password, host)

	msg := []byte(fmt.Sprintf(
		"Subject: Login confirmation\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n"+
			"Your code: %s\nExpires in 5 minutes",
		code,
	))

	return smtp.SendMail(
		addr,
		auth,
		from,
		[]string{to},
		msg,
	)
}

func (h *Handler) startSecondFactor(w http.ResponseWriter, username string) error {
	code := generateEmailCode()
	email, err := h.Service.SaveEmailCode(username, hashCode(code), time.Now().Add(5*time.Minute))
	if err != nil {
		return err
	}

	if err := sendEmailCode(email, code, h.Config.SMTP); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "pending_user",
		Value:    username,
		Path:     "/verify",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (h *Handler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		code := r.FormValue("code")
		log.Println(code)
		c, _ := r.Cookie("pending_user")
		username := c.Value
		user, err := h.Service.Auth.GetUserByUsername(username)
		if err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		ok, err := h.Service.Auth.CheckEmailCode(username, hashCode(code))
		if !ok {
			h.Service.AuthRiskIR.SaveAuthLog(models.AuthLog{UserID: user.Id,
				IP:     clientIP(r.RemoteAddr),
				Device: getDevice(r),
				Status: false,
				Reason: "fail auth by Invalid code"})
			h.Temp.ExecuteTemplate(w, "verify.html", "Invalid code")
			return
		}
		if err != nil {
			log.Println(err)
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Println("code okei")
		token, expired, err := h.Service.Auth.GetTokenByUsername(username)
		if err != nil {
			log.Println(err)
			h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		h.SetCookieAndSuccess(w, r, token, expired)
		h.Service.AuthRiskIR.SaveAuthLog(models.AuthLog{UserID: user.Id,
			IP:     clientIP(r.RemoteAddr),
			Device: getDevice(r),
			Status: true,
			Reason: "success login by 2 steps auth"})
	case http.MethodGet:
		h.Temp.ExecuteTemplate(w, "verify.html", nil)
		return
	}
}

func (h *Handler) SetCookieAndSuccess(w http.ResponseWriter, r *http.Request, token string, expired time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		Expires:  expired,
		HttpOnly: true,
		Secure:   true,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
