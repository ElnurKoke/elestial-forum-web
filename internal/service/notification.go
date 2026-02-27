package service

import (
	"forum/internal/models"
	"forum/internal/storage"
)

type ServiceMsgIR interface {
	CreateMassagePost(mes models.Message) error
	CreateMassageComment(mes models.Message) error
	CreateMassageUpRole(mes models.Message) error
	GetMessagesByAuthorId(id int) ([]models.Message, error)
	GetMessagesByReactAuthorId(id int) ([]models.Message, error)
}

type MsgService struct {
	storage storage.NotificationIR
}

func NewServiceMsg(NotificationIR storage.NotificationIR) ServiceMsgIR {
	return &MsgService{
		storage: NotificationIR,
	}
}

func (m *MsgService) CreateMassagePost(mes models.Message) error {
	return m.storage.CreateMassagePost(mes)
}

func (m *MsgService) CreateMassageUpRole(mes models.Message) error {
	return m.storage.CreateMassageUpRole(mes)
}

func (m *MsgService) CreateMassageComment(mes models.Message) error {
	return m.storage.CreateMassageComment(mes)
}

func (m *MsgService) GetMessagesByAuthorId(id int) ([]models.Message, error) {
	// if mes.Message == "cl" {
	// 	mes.Message = fmt.Sprintf(" %s liked comment: \"%s\" . Which was created by \"%s\"", mes.ReactAuthor, comm, mes.Author)
	// } else if mes.Message == "cd" {
	// 	mes.Message = fmt.Sprintf(" %s disliked comment: \"%s\". Which was created by \"%s\"", mes.ReactAuthor, comm, mes.Author)
	// } else if mes.Message == "pl" {
	// 	mes.Message = fmt.Sprintf(" %s loved post: \"%s\" . Which was created by \"%s\"", mes.ReactAuthor, comm, mes.Author)
	// } else if mes.Message == "pd" {
	// 	mes.Message = fmt.Sprintf("Oh no! %s disliked post: \"%s\". Which was created by \"%s\"", mes.ReactAuthor, comm, mes.Author)
	// } else if mes.Message == "cc" {
	// 	mes.Message = fmt.Sprintf(" %s commented on post: \"%s\". Which was created by \"%s\"", mes.ReactAuthor, comm, mes.Author)
	// }
	return m.storage.GetMessagesByAuthorId(id)
}

func (m *MsgService) GetMessagesByReactAuthorId(id int) ([]models.Message, error) {
	return m.storage.GetMessagesByReactAuthorId(id)
}
