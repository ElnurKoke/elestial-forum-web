package handler

import (
	"log"
	"net/http"
	"strings"

	"forum/internal/models"
)

func (h *Handler) signUp(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/signup" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		err := r.ParseForm()
		if err != nil {
			log.Println(err)
		}
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := r.FormValue("password")
		rpassword := r.FormValue("password1")
		if err := h.Service.Auth.CreateUser(models.User{Email: email, Username: username, Password: password, RepeatPassword: rpassword}); err != nil {
			info := models.InfoSign{
				Error:          err.Error(),
				Username:       username,
				Password:       password,
				RepeatPassword: rpassword,
				Email:          email,
			}
			if err := h.Temp.ExecuteTemplate(w, "signup.html", info); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}

		user, err := h.Service.Auth.GetUserByUsername(username)
		if err != nil {
			log.Println(err)
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if err := h.Service.CreateRiskAssessment(models.RiskAssessment{
			UserID:        user.Id,
			RiskLevel:     "YELLOW",
			PrimaryIP:     clientIP(r.RemoteAddr),
			PrimaryDevice: getDevice(r),
		}); err != nil {
			log.Println(err)
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		info := models.InfoSign{
			Error:    "You have successfully registered",
			Username: username,
		}
		if err := h.Temp.ExecuteTemplate(w, "signin.html", info); err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	case http.MethodGet:

		if err := h.Temp.ExecuteTemplate(w, "signup.html", nil); err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	default:
		h.ErrorPage(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func getDevice(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if ua == "" {
		return "unknown"
	}
	return ua
}
