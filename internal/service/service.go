package service

import "forum/internal/storage"

type Service struct {
	Auth
	AuthRiskIR
	ServicePostIR
	User
	CommentServiceIR
	EmotionServiceIR
	ServiceMsgIR
	CommunicationServiceIR
}

func NewService(storages *storage.Storage) *Service {
	return &Service{
		Auth:                   NewAuthService(storages),
		AuthRiskIR:             NewAuthRiskService(storages.AuthRiskIR),
		ServicePostIR:          NewPostService(storages.PostIR),
		User:                   NewUserService(storages),
		CommentServiceIR:       newCommentServ(storages.CommentIR),
		EmotionServiceIR:       NewEmotionService(storages.ReactionIR),
		ServiceMsgIR:           NewServiceMsg(storages.NotificationIR),
		CommunicationServiceIR: NewCommunicationService(storages.CommunicationIR),
	}
}
