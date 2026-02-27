package handler

import (
	"fmt"
	"forum/internal/models"
	"log"
	"net/http"
	"strconv"
)

func (h *Handler) deletePost(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/delete/post/" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if id == 0 || err != nil {
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
	if !user.IsAuth {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	res := r.Form.Get("isDelete")
	if res == "" {
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if res == "isDelete" {
		err = h.Service.ServicePostIR.DeletePost(id)
	} else {
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err != nil {
		h.ErrorPage(w, err.Error(), http.StatusBadRequest)
	}
	http.Redirect(w, r, "/post/myPost", http.StatusSeeOther)
}

func (h *Handler) changePost(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/change/post/" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if id == 0 || err != nil {
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
	if !user.IsAuth {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	title := r.FormValue("title")
	description := r.FormValue("description")
	categories := r.Form["category"]
	if len(categories) == 0 {
		h.ErrorPage(w, "INVALID CATEGORY, please select existing categories ", http.StatusBadRequest)
		return
	}
	if len(description) > 600 || len(description) == 0 {
		h.ErrorPage(w, "description should be shorter than 400 symbols and not empty", http.StatusBadRequest)
		return
	}
	if len(title) == 0 || len(title) >= 40 {
		h.ErrorPage(w, "INVALID TITLE, title should be shorter than 35 symbols and not empty", http.StatusBadRequest)
		return
	}
	if err := h.Service.ServicePostIR.UpdatePost(models.Post{
		Id:          id,
		Title:       title,
		Description: description,
		Category:    categories,
		Author:      user.Username,
	}); err != nil {
		fmt.Println("fix me")
		log.Fatal(err)
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err != nil {
		h.ErrorPage(w, err.Error(), http.StatusBadRequest)
	}
	http.Redirect(w, r, "/post/myPost", http.StatusSeeOther)
}
