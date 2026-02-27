package storage

import "database/sql"

type Storage struct {
	Auth
	AuthRiskIR
	PostIR
	User
	CommentIR
	ReactionIR
	NotificationIR
	CommunicationIR
}

func NewStorage(db *sql.DB) *Storage {
	return &Storage{
		Auth:            NewAuthStorage(db),
		AuthRiskIR:      NewAuthRiskStorage(db),
		PostIR:          NewPostStorage(db),
		User:            NewUserStorage(db),
		CommentIR:       newCommentStorage(db),
		ReactionIR:      NewEmotionSQL(db),
		NotificationIR:  NewNotificationStorage(db),
		CommunicationIR: NewCommunicationStore(db),
	}
}
