package storage

import (
	"database/sql"
	"forum/internal/models"
)

type AuthRiskIR interface {
	CreateRiskAssessment(assessment models.RiskAssessment) error
	UpdateRiskAssessment(assessment models.RiskAssessment) error
	GetRiskAssessmentByUserID(userID int) (models.RiskAssessment, error)
	SaveAuthLog(log models.AuthLog) error
	GetLogsByUserID(userID int) ([]models.AuthLog, error)
}

type AuthRiskStorage struct {
	db *sql.DB
}

func NewAuthRiskStorage(db *sql.DB) *AuthRiskStorage {
	return &AuthRiskStorage{db: db}
}

func (a *AuthRiskStorage) CreateRiskAssessment(assessment models.RiskAssessment) error {
	riskLevel := assessment.RiskLevel
	if riskLevel == "" {
		riskLevel = "YELLOW"
	}

	var primaryOnlineTime interface{}
	if !assessment.PrimaryOnlineTime.IsZero() {
		primaryOnlineTime = assessment.PrimaryOnlineTime
	}

	_, err := a.db.Exec(
		`INSERT INTO risk_assessments(
				user_id,
				risk_level,
				reason,
				primary_ip,
				primary_device,
				primary_online_time
			) VALUES ($1, $2, $3, $4, $5, $6)`,
		assessment.UserID,
		riskLevel,
		assessment.Reason,
		assessment.PrimaryIP,
		assessment.PrimaryDevice,
		primaryOnlineTime,
	)
	return err
}

func (a *AuthRiskStorage) UpdateRiskAssessment(assessment models.RiskAssessment) error {
	var primaryOnlineTime interface{}
	if !assessment.PrimaryOnlineTime.IsZero() {
		primaryOnlineTime = assessment.PrimaryOnlineTime
	}

	res, err := a.db.Exec(
		`UPDATE risk_assessments
			SET risk_level = $1,
			    reason = $2,
			    primary_geo = $3,
			    primary_ip = $4,
			    primary_device = $5,
			    primary_online_time = $6
			WHERE user_id = $7`,
		assessment.RiskLevel,
		assessment.Reason,
		assessment.PrimaryGeo,
		assessment.PrimaryIP,
		assessment.PrimaryDevice,
		primaryOnlineTime,
		assessment.UserID,
	)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (a *AuthRiskStorage) GetRiskAssessmentByUserID(userID int) (models.RiskAssessment, error) {
	var (
		assessment        models.RiskAssessment
		reason            sql.NullString
		primaryGeo        sql.NullString
		primaryIP         sql.NullString
		primaryDevice     sql.NullString
		primaryOnlineTime sql.NullTime
	)

	err := a.db.QueryRow(
		`SELECT user_id, risk_level, reason, primary_geo, primary_ip, primary_device, primary_online_time
			FROM risk_assessments
			WHERE user_id = $1 LIMIT 1`,
		userID,
	).Scan(
		&assessment.UserID,
		&assessment.RiskLevel,
		&reason,
		&primaryGeo,
		&primaryIP,
		&primaryDevice,
		&primaryOnlineTime,
	)
	if err != nil {
		return models.RiskAssessment{}, err
	}

	assessment.PrimaryGeo = primaryGeo.String
	assessment.PrimaryIP = primaryIP.String
	assessment.PrimaryDevice = primaryDevice.String
	assessment.Reason = reason.String
	if primaryOnlineTime.Valid {
		assessment.PrimaryOnlineTime = primaryOnlineTime.Time
	}

	logs, err := a.GetLogsByUserID(userID)
	if err != nil {
		return models.RiskAssessment{}, err
	}
	assessment.AuthLogs = logs

	return assessment, nil
}

func (a *AuthRiskStorage) SaveAuthLog(log models.AuthLog) error {
	_, err := a.db.Exec(
		`INSERT INTO user_events(user_id, ip, geo, device, status,reason, event_time)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		log.UserID,
		log.IP,
		log.Geo,
		log.Device,
		log.Status,
		log.Reason,
		log.Time,
	)
	return err
}

func (a *AuthRiskStorage) GetLogsByUserID(userID int) ([]models.AuthLog, error) {
	rows, err := a.db.Query(
		`SELECT id, user_id, ip, geo, device, status, reason, event_time
			FROM user_events
			WHERE user_id = $1
			ORDER BY event_time DESC
			LIMIT 10`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := make([]models.AuthLog, 0)
	for rows.Next() {
		var (
			logItem models.AuthLog
			ip      sql.NullString
			geo     sql.NullString
			device  sql.NullString
			status  sql.NullBool
			reason  sql.NullString
			tm      sql.NullTime
		)

		if err := rows.Scan(
			&logItem.ID,
			&logItem.UserID,
			&ip,
			&geo,
			&device,
			&status,
			&reason,
			&tm,
		); err != nil {
			return nil, err
		}

		logItem.IP = ip.String
		logItem.Geo = geo.String
		logItem.Device = device.String
		logItem.Status = status.Bool
		logItem.Reason = reason.String
		if tm.Valid {
			logItem.Time = tm.Time
		}

		logs = append(logs, logItem)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return logs, nil
}
