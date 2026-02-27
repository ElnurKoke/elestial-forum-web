package handler

import (
	"fmt"
	"forum/internal/models"
	"forum/internal/storage"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (h *Handler) profilePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/profile/" {
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

	profileUser := models.User{}

	posts, err := h.Service.ServicePostIR.GetMyPost(user.Id)
	if err != nil {
		h.ErrorPage(w, models.ErrPostNotFound.Error(), http.StatusNotFound)
		log.Println(err.Error())
		return
	}

	asks, err := h.Service.CommunicationServiceIR.GetAllAsks(user.Rol)
	if err != nil {
		h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		models.ErrLog.Println(err)
		return
	}
	model := models.ProfileInfo{
		User:        user,
		ProfileUser: profileUser,
		Posts:       posts,
		Askeds:      asks,
	}
	if user.Rol == "king" {
		alluser, err := h.Service.User.GetAllUser(user.Id)
		if err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			models.ErrLog.Println(err)
			return
		}
		model.AllUsers = alluser
		allcat, err := h.Service.ServicePostIR.GetCategories()
		if err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			models.ErrLog.Println(err)
			return
		}
		model.AllCategory = allcat
	} else if user.Rol == "moderator" {
		waitPosts, err := h.Service.ServicePostIR.GetAllWaitPosts()
		if err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			models.ErrLog.Println(err)
			return
		}
		model.WaitPosts = waitPosts
		a, err := h.Service.CommunicationServiceIR.GetCommunication("moderator")
		if err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			models.ErrLog.Println(err)
			return
		}
		model.RoleMsgs = a
	} else if user.Rol == "admin" {
		// if r.URL.Query().Get("show") == "modMsg" {
		// }
		a, err := h.Service.CommunicationServiceIR.GetCommunication("admin")
		if err != nil {
			h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			models.ErrLog.Println(err)
			return
		}
		model.RoleMsgs = a
	}
	switch r.Method {
	case http.MethodGet:

		if err := h.Temp.ExecuteTemplate(w, "profile.html", model); err != nil {
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
		if r.FormValue("form") == "username" { //---------------------------------------------------------------------name edit
			username := r.FormValue("username")
			if err := h.Service.User.UpdateUserName(user.Id, username); err != nil {
				info := models.ProfileInfo{
					Error:       err.Error(),
					User:        user,
					ProfileUser: profileUser,
					Posts:       posts,
				}
				if err := h.Temp.ExecuteTemplate(w, "profile.html", info); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}
			user.Username = username
			info := models.ProfileInfo{
				Error:       "You have successfully update name",
				User:        user,
				ProfileUser: profileUser,
				Posts:       posts,
			}
			if err := h.Temp.ExecuteTemplate(w, "profile.html", info); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else if r.FormValue("form") == "badComment" { //------------------------------------------------------------------warn comment
			if user.Rol != "moderator" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			strPostId := r.Form.Get("post_id")
			strCommentId := r.Form.Get("comment_id")
			message := r.Form.Get("text")
			post_id, _ := strconv.Atoi(strPostId)
			commentId, _ := strconv.Atoi(strCommentId)
			if err := h.Service.CreateCommunication(models.Communication{
				FromUserId:  user.Id,
				ForWhomRole: "admin",
				PostId:      post_id,
				CommentId:   commentId,
				Message:     message,
				MessageCode: fmt.Sprintf("%s-%s-%s", "admin", "comment", "bad")}); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			link := fmt.Sprintf("/post/?id=%d", post_id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "badPost" { //------------------------------------------------------------------warn post
			if user.Rol != "moderator" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			strPostId := r.Form.Get("post_id")
			message := r.Form.Get("text")
			post_id, _ := strconv.Atoi(strPostId)
			if err := h.Service.CreateCommunication(models.Communication{
				FromUserId:  user.Id,
				ForWhomRole: "admin",
				PostId:      post_id,
				Message:     message,
				MessageCode: fmt.Sprintf("%s-%s-%s", "admin", "post", "bad")}); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			link := fmt.Sprintf("/post/?id=%d", post_id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "crPost" { //------------------------------------------------------------------ask create post
			if user.Rol != "moderator" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			res := r.Form.Get("isCrPost")
			inf := strings.Split(res, ",")
			action := inf[0]
			strId := inf[1]
			post_id, err := strconv.Atoi(strId)
			if err != nil {
				models.ErrLog.Println(" Error strconv.Atoi: ", post_id)
				return
			}
			if err := h.Service.CommunicationServiceIR.ConfirmPost(post_id, action); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if err := h.Service.CreateCommunication(models.Communication{
				FromUserId:  user.Id,
				ForWhomRole: storage.UpRole(user.Rol),
				PostId:      post_id,
				MessageCode: fmt.Sprintf("%s-%s-%s", storage.UpRole(user.Rol), "post", "delete")}); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			link := fmt.Sprintf("/profile/?id=%d", user.Id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "role" { //---------------------------------------------------------------------role ask
			res := r.Form.Get("isLevelUp")
			if res == "isLevelUp" {
				if err := h.Service.CommunicationServiceIR.AskRole(models.Communication{FromUserId: user.Id, OldRole: user.Rol}); err != nil {
					info := models.ProfileInfo{
						Error:       err.Error(),
						User:        user,
						ProfileUser: profileUser,
						Posts:       posts,
					}
					if err := h.Temp.ExecuteTemplate(w, "profile.html", info); err != nil {
						h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
				info := models.ProfileInfo{
					Error:       "Your request for a role upgrade has been sent",
					User:        user,
					ProfileUser: profileUser,
					Posts:       posts,
				}
				if err := h.Temp.ExecuteTemplate(w, "profile.html", info); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			} else {
				models.ErrLog.Println("such control with a role is not provided")
				return
			}
		} else if r.FormValue("form") == "bio" { //---------------------------------------------------------------------bio edit
		} else if r.FormValue("form") == "ava" { //---------------------------------------------------------------------ava edit
		} else if r.FormValue("form") == "delCat" { //---------------------------------------------------------------------ava edit
			if user.Rol != "king" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			nameCategory := r.FormValue("name")
			if err := h.Service.ServicePostIR.DeleteCategory(nameCategory); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			link := fmt.Sprintf("/profile/?id=%d", user.Id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "addCat" { //---------------------------------------------------------------------ava edit
			if user.Rol != "king" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			nameCategory := r.FormValue("text")
			for _, exist := range model.AllCategory {
				if nameCategory == exist.Name {
					h.ErrorPage(w, "Category allready exists", http.StatusBadRequest)
					return
				}
			}
			if err := h.Service.ServicePostIR.AddCategory(nameCategory); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			link := fmt.Sprintf("/profile/?id=%d", user.Id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "modAns" { //-------------------------------------------------------------------reply moder mess
			if user.Rol != "admin" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			info := r.Form.Get("info")
			strPostId := r.Form.Get("post_id")
			message := r.Form.Get("text") + " -> reply to moderator: " + info
			post_id, _ := strconv.Atoi(strPostId)
			if err := h.Service.CreateCommunication(models.Communication{
				FromUserId:  user.Id,
				ForWhomRole: "moderator",
				PostId:      post_id,
				Message:     message,
				MessageCode: "moderator-answer"}); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			link := fmt.Sprintf("/profile/?id=%d", user.Id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "changeRole" { //--------------------------------------------------------------rol change
			if user.Rol != "king" {
				h.ErrorPage(w, "your role is not suitable", http.StatusBadRequest)
				return
			}
			res := r.Form.Get("isLevel")
			inf := strings.Split(res, ",")
			strId := inf[2]
			oldRole := inf[1]
			updown := inf[0]
			var newRole string
			if updown == "up" {
				newRole = storage.UpRole(oldRole)
			} else {
				newRole = storage.DownRole(oldRole)
			}

			id, err := strconv.Atoi(strId)
			if err != nil {
				models.ErrLog.Println(" Error strconv.Atoi: ", id)
				return
			}

			if err := h.Service.CommunicationServiceIR.UpUserRole(id, newRole); err != nil {
				info := models.ProfileInfo{
					Error:       err.Error(),
					User:        user,
					ProfileUser: profileUser,
					Posts:       posts,
				}
				if err := h.Temp.ExecuteTemplate(w, "profile.html", info); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}
			if err := h.Service.ServiceMsgIR.CreateMassageUpRole(models.Message{FromUserId: user.Id, ToUserId: id, Message: updown + "Role"}); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			link := fmt.Sprintf("/profile/?id=%d", user.Id)
			http.Redirect(w, r, link, http.StatusSeeOther)
		} else if r.FormValue("form") == "roleUp" { //---------------------------------------------------------------------up role
			res := r.Form.Get("isLevelUp")
			if strings.Contains(res, "accept") {
				id, err := strconv.Atoi(res[6:])
				if err != nil {
					models.ErrLog.Println(" Error strconv.Atoi: ", id)
					return
				}
				if err := h.Service.CommunicationServiceIR.UpUserRole(id, user.Rol); err != nil {
					info := models.ProfileInfo{
						Error:       err.Error(),
						User:        user,
						ProfileUser: profileUser,
						Posts:       posts,
					}
					if err := h.Temp.ExecuteTemplate(w, "profile.html", info); err != nil {
						h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					return
				}
				if err := h.Service.CommunicationServiceIR.DeleteAskRole(id); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				if err := h.Service.ServiceMsgIR.CreateMassageUpRole(models.Message{FromUserId: user.Id, ToUserId: id, Message: "upRole"}); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				link := fmt.Sprintf("/profile/?id=%d", user.Id)
				http.Redirect(w, r, link, http.StatusSeeOther)
			} else if strings.Contains(res, "refuse") {
				id, err := strconv.Atoi(res[6:])
				if err != nil {
					models.ErrLog.Println(" Error strconv.Atoi: ", id)
					return
				}
				if err := h.Service.CommunicationServiceIR.DeleteAskRole(id); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				if err := h.Service.ServiceMsgIR.CreateMassageUpRole(models.Message{FromUserId: user.Id, ToUserId: id, Message: "noRole"}); err != nil {
					h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				link := fmt.Sprintf("/profile/?id=%d", user.Id)
				http.Redirect(w, r, link, http.StatusSeeOther)
			} else {
				models.ErrLog.Println("such control with a role is not provided")
				return
			}
		} else {
			models.ErrLog.Println("this post request has not been looked at yet")
			h.ErrorPage(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
	default:
		h.ErrorPage(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
}
