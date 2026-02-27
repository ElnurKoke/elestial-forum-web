package handler

import (
	"forum/internal/models"
	"net/http"
)

func (h *Handler) info(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/about" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if err := h.Temp.ExecuteTemplate(w, "about.html", nil); err != nil {
		models.ErrLog.Println("h.Temp.ExecuteTemplate")
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
