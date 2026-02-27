package handler

import (
	"forum/internal/models"
	"log"
	"net/http"
	"sort"
)

func (h *Handler) notification(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/notification/" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	userValue := r.Context().Value("user")
	if userValue == nil {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var user models.User
	user, ok := userValue.(models.User)
	if !ok {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if !user.IsAuth {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	msgs, err := h.Service.ServiceMsgIR.GetMessagesByAuthorId(user.Id)
	sort.Sort(ByCreatedAtMes(msgs))
	if err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
	}
	msgsmy, err := h.Service.ServiceMsgIR.GetMessagesByReactAuthorId(user.Id)
	sort.Sort(ByCreatedAtMes(msgsmy))
	if err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
	}
	var messages models.InfoMsg
	if r.URL.Query().Has("myactions") {
		messages = models.InfoMsg{
			User:          user,
			Notifications: nil,
			Actions:       msgsmy,
		}
	} else if r.URL.Query().Has("newnotification") {
		messages = models.InfoMsg{
			User:          user,
			Notifications: msgs,
			Actions:       nil,
		}
	} else {
		messages = models.InfoMsg{
			User:          user,
			Notifications: msgs,
			Actions:       msgsmy,
		}
	}

	switch r.Method {
	case http.MethodPost:
		// err := r.ParseForm()
		// if err != nil {
		// 	log.Println(err)
		// }
		// username := r.FormValue("username")
		// password := r.FormValue("password")

		// token, expired, err := h.Service.CheckUser(models.User{
		// 	Username: username,
		// 	Password: password,
		// })
		// if err != nil {
		// 	h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		// 	return
		// }
		// http.SetCookie(w, &http.Cookie{
		// 	Name:    "token",
		// 	Value:   token,
		// 	Path:    "/",
		// 	Expires: expired,
		// })
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case http.MethodGet:

		if err := h.Temp.ExecuteTemplate(w, "notification.html", messages); err != nil {
			log.Println(err.Error())
			h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
		}
	default:
		h.ErrorPage(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}
