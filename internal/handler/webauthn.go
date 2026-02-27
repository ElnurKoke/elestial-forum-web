package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"forum/internal/models"
	"io"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func (h *Handler) WebAuthnRegisterStart(w http.ResponseWriter, r *http.Request) {
	userValue := r.Context().Value("user")
	if userValue == nil {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	user, ok := userValue.(models.User)
	if !ok {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	if !user.IsAuth {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	user.Credentials = []webauthn.Credential{}
	options, sessionData, err := models.WebAuthn.BeginRegistration(
		&user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		http.Error(w, "begin registration failed", http.StatusInternalServerError)
		return
	}

	// 4️⃣ Создаём sessionID
	sessionID := fmt.Sprintf(
		"webauthn:reg:%d:%s",
		user.Id,
		uuid.NewString(),
	)

	// 5️⃣ Сохраняем sessionData в Redis
	if err := h.sessionStore.Save(r.Context(), sessionID, sessionData); err != nil {
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	// 6️⃣ Кладём sessionID в cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_reg",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 минут
	})

	// 7️⃣ Отдаём options браузеру
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (h *Handler) WebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1️⃣ Получаем пользователя из context (ОБЯЗАТЕЛЬНО pointer)
	userValue := ctx.Value("user")
	if userValue == nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	user, ok := userValue.(models.User)
	if !ok || !user.IsAuth {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// 2️⃣ Читаем cookie с sessionID
	cookie, err := r.Cookie("webauthn_reg")
	if err != nil {
		http.Error(w, "registration session missing", http.StatusBadRequest)
		return
	}

	sessionID := cookie.Value

	// 3️⃣ Забираем SessionData из Redis
	sessionData, err := h.sessionStore.Get(ctx, sessionID)
	if err != nil {
		http.Error(w, "registration session expired", http.StatusBadRequest)
		return
	}

	// 4️⃣ FinishRegistration (КЛЮЧЕВО)
	credential, err := models.WebAuthn.FinishRegistration(
		&user,
		*sessionData,
		r,
	)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 5️⃣ Сохраняем credential в БД
	err = h.Service.Auth.SaveCredentials(&models.WebAuthnCredential{
		UserID:       int64(user.Id),
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		SignCount:    credential.Authenticator.SignCount,
		IsPasskey:    credential.Flags.BackupEligible,

		// BackupEligible: credential.Flags.BackupEligible,
		// BackupState:    credential.Flags.BackupState,
	})
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "failed to save credential", http.StatusInternalServerError)
		return
	}

	// 6️⃣ Удаляем session из Redis
	_ = h.sessionStore.Delete(ctx, sessionID)

	// 7️⃣ Удаляем cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_reg",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) WebAuthnLoginStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1️⃣ Пользователь может быть НЕ авторизован
	// логин по email / username приходит из формы
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	user, err := h.Service.User.GetUserByEmail(req.Email)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// 2️⃣ Загружаем credentials пользователя
	creds, err := h.Service.Auth.GetCredentials(user.Id)
	if err != nil || len(creds) == 0 {
		http.Error(w, "no passkeys on your device", http.StatusBadRequest)
		return
	}
	user.Credentials = creds

	// 3️⃣ BeginLogin
	options, sessionData, err := models.WebAuthn.BeginLogin(&user)
	if err != nil {
		http.Error(w, "begin login failed", http.StatusInternalServerError)
		return
	}

	// 4️⃣ sessionID
	sessionID := fmt.Sprintf(
		"webauthn:login:%d:%s",
		user.Id,
		uuid.NewString(),
	)

	// 5️⃣ save session
	if err := h.sessionStore.Save(ctx, sessionID, sessionData); err != nil {
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	// 6️⃣ cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "webauthn_login",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})

	// 7️⃣ send options
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (h *Handler) WebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1️⃣ cookie
	cookie, err := r.Cookie("webauthn_login")
	if err != nil {
		http.Error(w, "login session missing", http.StatusBadRequest)
		return
	}

	sessionID := cookie.Value

	// 2️⃣ sessionData
	sessionData, err := h.sessionStore.Get(ctx, sessionID)
	if err != nil {
		http.Error(w, "login session expired", http.StatusBadRequest)
		return
	}

	// 3️⃣ parse credential
	bodyBytes, _ := io.ReadAll(r.Body)
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "invalid assertion", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 4️⃣ userHandle → user
	userID, err := h.Service.Auth.GetUserIDByCredentialID(parsed.RawID)
	if err != nil {
		http.Error(w, "credential not found", http.StatusUnauthorized)
		return
	}

	fmt.Println(userID)

	user, err := h.Service.User.GetUserById(userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}
	log.Println(user)
	// 5️⃣ load credentials
	creds, err := h.Service.Auth.GetCredentials(user.Id)
	if err != nil {
		http.Error(w, "credentials error", http.StatusInternalServerError)
		return
	}

	user.Credentials = creds
	// 6️⃣ FinishLogin
	credential, err := models.WebAuthn.FinishLogin(
		&user,
		*sessionData,
		r,
	)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, "assertion failed", http.StatusUnauthorized)
		return
	}

	// 7️⃣ update signCount
	if err := h.Service.Auth.UpdateSignCount(
		credential.ID,
		credential.Authenticator.SignCount,
	); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	log.Println("UpdateSignCount")
	// 8️⃣ create auth session
	token, expired, err := h.Service.Auth.CreateSession(user.Username)
	log.Println(expired)
	// 9️⃣ cleanup
	if err := h.sessionStore.Delete(ctx, sessionID); err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "webauthn_login",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		Expires:  expired,
		HttpOnly: true,
		Secure:   true,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
	h.Service.AuthRiskIR.SaveAuthLog(models.AuthLog{UserID: userID,
		IP:     clientIP(r.RemoteAddr),
		Device: getDevice(r),
		Status: true,
		Reason: "success login by webauthn"})
}
