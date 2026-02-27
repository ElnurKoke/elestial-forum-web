package handler

import (
	"fmt"
	"forum/internal/models"
	"log"
	"net/http"
	"strconv"
)

func (h *Handler) emotionComment(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/emotion/comment/" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	commentId, err := strconv.Atoi(r.URL.Query().Get("id"))
	postId, err := strconv.Atoi(r.URL.Query().Get("postid"))
	if commentId == 0 || err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	// var post models.Post
	var comment models.Comment
	// post, _ = h.Service.ServicePostIR.GetPostId(postId)
	comment, _ = h.Service.GetCommentsByIdComment(commentId)
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
	if user.Username == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if !user.IsAuth {
		models.ErrLog.Println(http.StatusUnauthorized)
		h.ErrorPage(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	res := r.Form.Get("islike")
	if res == "" {
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var havemo bool
	if res == "like" {
		err, havemo = h.Service.EmotionServiceIR.CreateOrUpdateEmotionComment(models.Like{UserID: user.Id, CommentID: commentId, Islike: 1})
		if !havemo {
			err = h.Service.ServiceMsgIR.CreateMassageComment(models.Message{
				PostId: postId, CommentId: commentId, FromUserId: user.Id, ToUserId: comment.UserId, Message: "cl"})
			if err != nil {
				models.ErrLog.Println(postId, commentId, user.Id, comment.UserId, " --like comment:", err)
			}
		}

	} else if res == "dislike" {
		err, havemo = h.Service.EmotionServiceIR.CreateOrUpdateEmotionComment(models.Like{UserID: user.Id, CommentID: commentId, Islike: 0})
		if !havemo {
			err = h.Service.ServiceMsgIR.CreateMassageComment(models.Message{
				PostId: postId, CommentId: commentId, FromUserId: user.Id, ToUserId: comment.UserId, Message: "cd"})
		}

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

func (h *Handler) emotionPost(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/emotion/post/" {
		h.ErrorPage(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	postId, err := strconv.Atoi(r.URL.Query().Get("id"))
	post, err := h.Service.ServicePostIR.GetPostId(postId)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if postId == 0 || err != nil {
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
	if user.Username == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		log.Println(err.Error())
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	res := r.Form.Get("islike")
	if res == "" {
		h.ErrorPage(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	var havemo bool
	if res == "like" {
		err, havemo = h.Service.EmotionServiceIR.CreateOrUpdateEmotionPost(models.Like{UserID: user.Id, PostID: postId, Islike: 1})
		if !havemo {
			err = h.Service.ServiceMsgIR.CreateMassagePost(models.Message{
				PostId: postId, FromUserId: user.Id, ToUserId: post.UserId, Message: "pl"})
		}

	} else if res == "dislike" {
		err, havemo = h.Service.EmotionServiceIR.CreateOrUpdateEmotionPost(models.Like{UserID: user.Id, PostID: postId, Islike: 0})
		if !havemo {
			err = h.Service.ServiceMsgIR.CreateMassagePost(models.Message{
				PostId: postId, FromUserId: user.Id, ToUserId: post.UserId, Message: "pd"})
		}

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
