package handler

import (
	"forum/internal/service"
	svr "forum/internal/server"
	"forum/internal/storage"
	"html/template"
	"net/http"
	"path/filepath"
	"time"
)

type Handler struct {
	Mux          *http.ServeMux
	Temp         *template.Template
	Service      *service.Service
	Config       svr.Config
	sessionStore *service.RedisWebAuthnSessionStore
}

func NewHandler(services *service.Service, config svr.Config) *Handler {
	return &Handler{
		Mux:     http.NewServeMux(),
		Temp:    template.Must(template.ParseGlob("./front/html/*.html")),
		Service: services,
		Config:  config,
		sessionStore: service.NewRedisWebAuthnSessionStore(
			storage.RDB,
			5*time.Minute,
		),
	}
}

func (h *Handler) InitRoutes() http.Handler {

	h.Mux.HandleFunc("/", h.middleWareGetUser(h.homePage))
	h.Mux.HandleFunc("/profile/", h.middleWareGetUser(h.profilePage))
	h.Mux.HandleFunc("/about", h.middleWareGetUser(h.info))

	h.Mux.HandleFunc("/signup", h.middleWareGetUser(h.signUp))
	h.Mux.HandleFunc("/signin", h.signIn)
	h.Mux.HandleFunc("/verify", h.verifyEmail)
	h.Mux.HandleFunc("/passkey3fa", h.passkeyLogin)

	h.Mux.HandleFunc("/auth/google", h.googleAuth)
	h.Mux.HandleFunc("/oauth2callback-google", h.googleAuthCallback)
	h.Mux.HandleFunc("/auth/google/callback", h.googleAuthCallback)

	h.Mux.HandleFunc("/login/github/", h.githubLogin)
	h.Mux.HandleFunc("/oauth2callback", h.githubCallback)
	h.Mux.HandleFunc("/login/github/callback", h.githubCallback)

	h.Mux.HandleFunc("/post/", h.middleWareGetUser(h.postPage))
	h.Mux.HandleFunc("/post/create", h.middleWareGetUser(h.createPost))
	h.Mux.HandleFunc("/post/myPost", h.middleWareGetUser(h.myPost))
	h.Mux.HandleFunc("/post/myLikedPost", h.middleWareGetUser(h.myLikedPost))

	h.Mux.HandleFunc("/emotion/post/", h.middleWareGetUser(h.emotionPost))
	h.Mux.HandleFunc("/emotion/comment/", h.middleWareGetUser(h.emotionComment))

	h.Mux.HandleFunc("/delete/post/", h.middleWareGetUser(h.deletePost))
	h.Mux.HandleFunc("/delete/comment/", h.middleWareGetUser(h.deleteComment))

	h.Mux.HandleFunc("/comment/", h.middleWareGetUser(h.commentPage))

	h.Mux.HandleFunc("/change/post/", h.middleWareGetUser(h.changePost))

	h.Mux.HandleFunc("/notification/", h.middleWareGetUser(h.notification))
	h.Mux.HandleFunc("/settings/", h.middleWareGetUser(h.settings))

	h.Mux.HandleFunc("/webauthn/register/start", h.middleWareGetUser(h.WebAuthnRegisterStart))
	h.Mux.HandleFunc("/webauthn/register/finish", h.middleWareGetUser(h.WebAuthnRegisterFinish))

	h.Mux.HandleFunc("/webauthn/login/start", h.middleWareGetUser(h.WebAuthnLoginStart))
	h.Mux.HandleFunc("/webauthn/login/finish", h.middleWareGetUser(h.WebAuthnLoginFinish))

	h.Mux.HandleFunc("/webauthn/credentials/delete", h.middleWareGetUser(h.DeleteCredentials))

	h.Mux.HandleFunc("/logout", h.logOut)
	fileServer := http.FileServer(neuteredFileSystem{http.Dir("./front/static/")})
	h.Mux.Handle("/static", http.NotFoundHandler())
	h.Mux.Handle("/static/", http.StripPrefix("/static", fileServer))
	return h.Mux
}

type neuteredFileSystem struct {
	fs http.FileSystem
}

func (nfs neuteredFileSystem) Open(path string) (http.File, error) {
	f, err := nfs.fs.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if s.IsDir() {
		index := filepath.Join(path, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			closeErr := f.Close()
			if closeErr != nil {
				return nil, closeErr
			}

			return nil, err
		}
	}

	return f, nil
}
