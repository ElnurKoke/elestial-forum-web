package handler

import (
	"database/sql"
	"errors"
	"forum/internal/models"
	"log"
	"net/http"
)

func (h *Handler) homePage(w http.ResponseWriter, r *http.Request) {
	var posts []models.Post
	if r.URL.Path != "/" {
		models.ErrLog.Println(http.StatusNotFound)
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	userValue := r.Context().Value("user")
	if userValue == nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	user, ok := userValue.(models.User)
	if !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		h.ErrorPage(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	categories, err := h.Service.GetCategories()
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if r.URL.Query().Has("category") {
		category := r.URL.Query().Get("category")
		if !inSlice(category, categories) {
			h.ErrorPage(w, "Not exist page", http.StatusBadRequest)
			return
		}
		posts, err = h.Service.ServicePostIR.GetAllPostsByCategories(category)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	} else {
		posts, err = h.Service.ServicePostIR.GetAllPosts()
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	info := models.InfoPosts{
		user,
		posts,
		categories,
	}
	if err := h.Temp.ExecuteTemplate(w, "homepage.html", info); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
	}
}

func inSlice(val string, slice []models.Category) bool {
	for _, item := range slice {
		if item.Name == val {
			return true
		}
	}
	return false
}

func toString(cat []models.Category) []string {
	mas := []string{}
	for _, i := range cat {
		mas = append(mas, i.Name)
	}
	return mas
}
