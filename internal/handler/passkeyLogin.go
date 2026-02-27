package handler

import "net/http"

func (h *Handler) passkeyLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodGet:
		h.Temp.ExecuteTemplate(w, "loginPasskey.html", nil)
	default:
		h.ErrorPage(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}
