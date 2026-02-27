package service

import (
	"forum/internal/models"
	"forum/internal/storage"
)

type AuthRiskIR interface {
	CreateRiskAssessment(assessment models.RiskAssessment) error
	UpdateRiskAssessment(assessment models.RiskAssessment) error
	GetRiskAssessmentByUserID(userID int) (models.RiskAssessment, error)
	SaveAuthLog(log models.AuthLog) error
	GetLogsByUserID(userID int) ([]models.AuthLog, error)
}

type AuthRiskService struct {
	storage storage.AuthRiskIR
}

func NewAuthRiskService(storage storage.AuthRiskIR) AuthRiskIR {
	return &AuthRiskService{
		storage: storage,
	}
}

func (a *AuthRiskService) CreateRiskAssessment(assessment models.RiskAssessment) error {
	return a.storage.CreateRiskAssessment(assessment)
}

func (a *AuthRiskService) UpdateRiskAssessment(assessment models.RiskAssessment) error {
	return a.storage.UpdateRiskAssessment(assessment)
}

func (a *AuthRiskService) GetRiskAssessmentByUserID(userID int) (models.RiskAssessment, error) {
	return a.storage.GetRiskAssessmentByUserID(userID)
}

func (a *AuthRiskService) SaveAuthLog(log models.AuthLog) error {
	return a.storage.SaveAuthLog(log)
}

func (a *AuthRiskService) GetLogsByUserID(userID int) ([]models.AuthLog, error) {
	return a.storage.GetLogsByUserID(userID)
}
