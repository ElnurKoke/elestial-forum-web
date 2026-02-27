package handler

import (
	"forum/internal/models"
	"log"
	"net/http"
)

func (h *Handler) myLikedPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.ErrorPage(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	posts, err := h.Service.GetMyLikePost(user.Id)
	if err != nil {
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := models.InfoPosts{
		user,
		posts,
		nil,
	}
	if err := h.Temp.ExecuteTemplate(w, "myLikedPost.html", info); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
	}
}
