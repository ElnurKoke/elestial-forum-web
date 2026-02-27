package handler

import (
	"forum/internal/models"
	"log"
	"net/http"
	"sort"
)

func (h *Handler) myPost(w http.ResponseWriter, r *http.Request) {
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
	posts, err := h.Service.GetMyPost(user.Id)
	if err != nil {
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sort.Sort(ByCreatedAt(posts))
	info := models.InfoPosts{
		User:     user,
		Posts:    posts,
		Category: nil,
	}

	if err := h.Temp.ExecuteTemplate(w, "myPost.html", info); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
	}
}
