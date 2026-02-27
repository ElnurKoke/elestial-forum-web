package storage

import (
	"log"

	"forum/internal/models"

	"github.com/go-webauthn/webauthn/webauthn"
)

func InitWebAuthn() {
	var err error
	models.WebAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Elestial",
		RPID:          "localhost",
		RPOrigins:     []string{"https://localhost:8080"},
	})
	if err != nil {
		log.Fatal(err)
	}
}
