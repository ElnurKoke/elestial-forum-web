package handler

import (
	"fmt"
	"forum/internal/models"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/uuid"
)

func (h *Handler) createPost(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/post/create" {
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
	categories, err := h.Service.ServicePostIR.GetCategories()
	if err != nil {
		h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodPost:
		err := r.ParseMultipartForm(20 << 20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.ContentLength > 20*1024*1024 {
			h.ErrorPage(w, "File size exceeds the limit of 20 MB", http.StatusRequestEntityTooLarge)
			return
		}
		title := r.FormValue("title")
		description := r.FormValue("description")
		categories := r.Form["category"]
		file, handler, err := r.FormFile("image")
		if err != nil {
			h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()
		_, err = checkImageSignature(file)
		if err != nil {
			h.ErrorPage(w, err.Error(), http.StatusBadRequest)
			return
		}

		uniqueID, err := uuid.NewV4()
		if err != nil {
			h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filename := strings.Replace(uniqueID.String(), "-", "", -1)
		prevname := filepath.Base(handler.Filename)
		fileExt := filepath.Ext(prevname)

		if fileExt != ".jpeg" && fileExt != ".png" && fileExt != ".gif" && fileExt != ".jpg" {
			h.ErrorPage(w, err.Error(), http.StatusBadRequest)
			return
		}
		image := fmt.Sprintf("%s%s", filename, fileExt)
		imagePath := "./front/static/data/" + image
		f, err := os.Create(imagePath)
		if err != nil {
			h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		_, err = io.Copy(f, file)
		if err != nil {
			h.ErrorPage(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := h.Service.ServicePostIR.CreatePost(models.Post{
			Title:       title,
			Description: description,
			Image:       image,
			Category:    categories,
			UserId:      user.Id,
		}); err != nil {
			h.ErrorPage(w, err.Error(), http.StatusBadRequest)
			return
		}
		if user.Rol == "king" || user.Rol == "admin" || user.Rol == "moderator" {
			if err := h.Service.CommunicationServiceIR.ConfirmPost(0, "forking"); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case http.MethodGet:
		if err := h.Temp.ExecuteTemplate(w, "postCreate.html", categories); err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	default:
		h.ErrorPage(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
}
