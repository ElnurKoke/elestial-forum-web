package handler

import (
	"context"
	"forum/internal/models"
	"net/http"
	"sync"
	"time"
)

func (h *Handler) middleWareGetUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		var user models.User
		c, err := r.Cookie("token")
		if err != nil {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user", models.User{})))
			return
		}
		user, err = h.Service.GetUserByToken(c.Value)
		if err != nil {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user", models.User{})))
			return
		}
		if user.ExpiresAt.Before(time.Now()) {
			if err := h.Service.DeleteToken(c.Value); err != nil {
				h.ErrorPage(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		user.IsAuth = true

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user", user)))

	}
}

type client struct {
	requests int
	lastSeen time.Time
}

var (
	clients = make(map[string]*client)
	mu      sync.Mutex
)

const (
	maxRequests = 10
	window      = time.Minute
)
