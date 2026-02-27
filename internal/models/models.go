package models

import (
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
)

type User struct {
	Id             int
	Email          string
	Username       string
	Password       string
	RepeatPassword string
	ExpiresAt      *time.Time
	IsAuth         bool
	ImageBack      string
	ImageURL       string
	Rol            string
	Bio            string
	Created_at     time.Time
	Updated_at     time.Time
	Credentials    []webauthn.Credential
}

type GoogleLoginUserData struct {
	ID        uuid.UUID
	Name      string
	Email     string
	Password  string
	Role      string
	Photo     string
	Verified  bool
	Provider  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GithubUserData struct {
	Login  string `json:"login"`
	ID     int    `json:"id"`
	NodeID string `json:"node_id"`
}

type Post struct {
	Id          int
	Title       string
	Description string
	Image       string
	Category    []string
	UserId      int
	Author      string
	Likes       int
	Dislikes    int
	Status      string
	CreateAt    time.Time
}

type Message struct {
	Id            int
	PostId        int
	CommentId     int
	FromUserId    int
	ToUserId      int
	Author        string
	ReactAuthor   string
	Message       string
	Active        int
	FromUserName  string
	AvaImage      string
	PostImage     string
	FromUserImage string
	CreateAt      time.Time
}

type Comment struct {
	Id         int
	PostId     int
	UserId     int
	Creator    string
	Text       string
	Likes      int
	Dislikes   int
	IsAuth     bool
	Created_at time.Time
}

type Like struct {
	UserID       int
	PostID       int
	Islike       int
	CommentID    int
	CountLike    int
	Countdislike int
}

type Category struct {
	Name string
}

type Communication struct {
	Id            int
	FromUserId    int
	FromUserName  string
	ForWhomRole   string
	OldRole       string
	NewRole       string
	AboutUserId   int
	AboutUserName string
	PostId        int
	PostImage     string
	CommentId     int
	CommentText   string
	Message       string
	MessageCode   string
	CreatedAt     time.Time
}

type WebAuthnCredential struct {
	ID             int64     // id
	UserID         int64     // user_id
	CredentialID   []byte    // credential_id (BLOB)
	PublicKey      []byte    // public_key (BLOB)
	SignCount      uint32    // sign_count
	IsPasskey      bool      // is_passkey
	CreatedAt      time.Time // created_at
	LastUsedAt     time.Time // last_used_at
	BackupEligible bool
	BackupState    bool
}

var WebAuthn *webauthn.WebAuthn

func (u *User) WebAuthnID() []byte {
	return []byte(strconv.FormatInt(int64(u.Id), 10))
}

func (u *User) WebAuthnName() string {
	return u.Username
}

func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

func (u *User) WebAuthnIcon() string {
	return ""
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}
