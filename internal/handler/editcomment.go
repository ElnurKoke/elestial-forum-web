package handler

import (
	"fmt"
	"forum/internal/models"
	"log"
	"net/http"
	"strconv"
)

func (h *Handler) commentPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/comment/" {
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
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if !user.IsAuth {
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	commentinfo, err := h.Service.CommentServiceIR.GetCommentsByIdComment(id)
	if err != nil {
		h.ErrorPage(w, models.ErrCommentNotFound.Error(), http.StatusNotFound)
		log.Println(err.Error())
		return
	}

	if user.Username != commentinfo.Creator {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if err = h.Temp.ExecuteTemplate(w, "comment.html", commentinfo); err != nil {
			log.Println(err.Error())
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		return
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			h.ErrorPage(w, "Bad request", http.StatusBadRequest)
			return
		}
		commentText := r.FormValue("text")

		if commentText == "" {
			h.ErrorPage(w, "comment field not found (empty comment)", http.StatusBadRequest)

			return
		}
		if len(commentText) > 300 {
			h.ErrorPage(w, "comment should be shorter than 300 symbols", http.StatusBadRequest)
			return
		}
		commentinfo.Text = commentText
		commentinfo.Id = id
		if err := h.Service.CommentServiceIR.UpdateComment(commentinfo); err != nil {
			h.ErrorPage(w, err.Error(), http.StatusBadRequest)
			return
		}
		link := fmt.Sprintf("/post/?id=%d", commentinfo.PostId)
		http.Redirect(w, r, link, http.StatusSeeOther)
	default:
		h.ErrorPage(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (h *Handler) deleteComment(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/delete/comment/" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	commentId, err := strconv.Atoi(r.URL.Query().Get("id"))
	postId, err := strconv.Atoi(r.URL.Query().Get("postid"))
	if commentId == 0 || err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	userValue := r.Context().Value("user")
	if userValue == nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var user models.User
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
	// fmt.Println(res)
	if res == "isDelete" {
		err = h.Service.CommentServiceIR.DeleteComment(commentId)
	} else {
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err != nil {
		h.ErrorPage(w, err.Error(), http.StatusBadRequest)
	}
	link := fmt.Sprintf("/post/?id=%d", postId)
	http.Redirect(w, r, link, http.StatusSeeOther)
}
