package service

import (
	"fmt"
	"forum/internal/models"
	"forum/internal/storage"
	"time"
)

type CommunicationServiceIR interface {
	CreateCommunication(mes models.Communication) error
	AskRole(mes models.Communication) error
	GetAllAsks(role string) ([]models.Communication, error)
	GetCommunication(role string) ([]models.Communication, error)
	UpUserRole(id int, newrole string) error
	ConfirmPost(id int, action string) error
	DeleteAskRole(id int) error
}

type CommunicationService struct {
	storage storage.CommunicationIR
}

func NewCommunicationService(CommunicationIR storage.CommunicationIR) CommunicationServiceIR {
	return &CommunicationService{
		storage: CommunicationIR,
	}
}
func (c *CommunicationService) CreateCommunication(mes models.Communication) error {
	return c.storage.CreateCommunication(mes)
}

func (c *CommunicationService) ConfirmPost(id int, action string) error {
	return c.storage.ConfirmPost(id, action)
}

func (c *CommunicationService) GetAllAsks(role string) ([]models.Communication, error) {
	return c.storage.GetAllAsks(role)
}

func (c *CommunicationService) GetCommunication(role string) ([]models.Communication, error) {
	return c.storage.GetCommunication(role)
}

func (c *CommunicationService) UpUserRole(id int, newrole string) error {
	return c.storage.UpUserRole(id, newrole)
}

func (c *CommunicationService) DeleteAskRole(id int) error {
	return c.storage.DeleteAskRole(id)
}

func (c *CommunicationService) AskRole(mes models.Communication) error {
	lastrequestTime, err := c.storage.GetTimeAskRole(mes.FromUserId)
	if err != nil {
		models.ErrLog.Println(err)
	}
	check, err := checkTime(lastrequestTime)
	if err != nil {
		models.ErrLog.Println(err)
		return err
	}
	if !check {
		return err
	}
	return c.storage.AskRole(mes)
}

func checkTime(input time.Time) (bool, error) {
	currentTime := time.Now()

	twoDaysLater := input.Add(24 * time.Hour)

	if currentTime.Before(twoDaysLater) {
		remainingTime := twoDaysLater.Sub(currentTime)
		return false, fmt.Errorf("Please wait %.0f hour", remainingTime.Hours())
	}

	return true, nil
}
