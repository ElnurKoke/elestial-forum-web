package test

import (
	"forum/internal/handler"
	"forum/internal/service"
	"forum/internal/storage"
	"net/http"
	"net/http/httptest"
	"testing"
)

func homePage_test(t *testing.T) {
	db := storage.InitDB()
	store := storage.NewStorage(db)
	services := service.NewService(store)
	handlers := handler.NewHandler(services)
	server:= httptest.NewServer(http.HandleFunc(&handler.Handler.))


}
