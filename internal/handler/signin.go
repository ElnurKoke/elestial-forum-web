package handler

import (
	"errors"
	"forum/internal/models"
	"log"
	"net/http"
	"strings"
)

func (h *Handler) signIn(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/signin" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.handleSignInPost(w, r)
	case http.MethodGet:

		if err := h.Temp.ExecuteTemplate(w, "signin.html", nil); err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	default:
		h.ErrorPage(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}

func (h *Handler) handleSignInPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		models.ErrLog.Printf("failed to parse sign-in form: %v", err)
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// Step 1:(username + password).
	token, expired, err := h.verifyPrimaryAuth(r, username, password)
	if err != nil {
		if errors.Is(err, errServiceUnavailable) {
			h.ErrorPage(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}
		if errors.Is(err, errTooManyAttempts) {
			h.ErrorPage(w, "Too many attempts", http.StatusTooManyRequests)
			return
		}
		if errors.Is(err, models.ErrPasswordDoesNotMatch) {
			user, err := h.Service.Auth.GetUserByUsername(username)
			if err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if err := h.Service.AuthRiskIR.SaveAuthLog(models.AuthLog{UserID: user.Id,
				IP:     clientIP(r.RemoteAddr),
				Device: getDevice(r),
				Status: false,
				Reason: "fail auth password does not match"}); err != nil {
			}
		}
		h.renderSignInFormError(w, err.Error(), username)
		models.InfoLog.Printf("URL: %s\n        Method:   %s\n        Message:  %s\n        Status:   %s\n", r.URL.Path, r.Method, err, "fail")
		return
	}

	user, err := h.Service.Auth.GetUserByUsername(username)
	if err != nil {
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	riskState, err := h.Service.GetRiskAssessmentByUserID(user.Id)
	if err != nil {
		log.Println(err)
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h.updateRiskLevelByLogsAsync(user.Id, riskState)

	switch riskState.RiskLevel {
	case "GREEN":
		if err := h.Service.AuthRiskIR.SaveAuthLog(models.AuthLog{UserID: user.Id,
			IP:     clientIP(r.RemoteAddr),
			Device: getDevice(r),
			Status: true,
			Reason: "success login by 1 step auth"}); err != nil {
		}
		h.SetCookieAndSuccess(w, r, token, expired)
	case "YELLOW":
		if err := h.startSecondFactor(w, username); err != nil {
			log.Println(err)
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/verify", http.StatusSeeOther)
	case "RED":
		http.Redirect(w, r, "/passkey3fa", http.StatusSeeOther)
	default:
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
