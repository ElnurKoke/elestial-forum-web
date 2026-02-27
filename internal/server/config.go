package server

import (
	"encoding/json"
	"forum/internal/models"
	"os"
)

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

type GithubOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

type OAuthConfig struct {
	Google GoogleOAuthConfig
	Github GithubOAuthConfig
}

type Config struct {
	Port string
	DB   struct {
		Dsn    string
		Driver string
	}
	SMTP struct {
		From     string
		Password string
		Host     string
		Port     string
	}
	LLM struct {
		APIURL string
	}
	Redis struct {
		Addr     string
		Password string
		DB       int
	}
	OAuth OAuthConfig
}

func NewConfig() (Config, error) {
	// Открываем JSON-файл с конфигурацией.
	configFile, err := os.Open("config.json")
	if err != nil {
		return Config{}, err
	}
	defer configFile.Close()
	// Декодируем JSON-файл в структуру Config.
	var config Config
	decoder := json.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		return Config{}, err
	}
	models.InfoLog.Println("Configuration extraction successful")
	return config, nil
}
