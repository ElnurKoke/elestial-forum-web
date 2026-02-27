package models

import "time"

type AuthLog struct {
	ID     int       `json:"id"`
	UserID int       `json:"user_id"`
	IP     string    `json:"ip,omitempty"`
	Device string    `json:"device,omitempty"`
	Geo    string    `json:"geo,omitempty"`
	Status bool      `json:"status,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Time   time.Time `json:"event_time,omitempty"`
}

type RiskAssessment struct {
	UserID            int       `json:"user_id"`
	RiskLevel         string    `json:"risk_level"`
	Reason            string    `json:"reason"`
	PrimaryGeo        string    `json:"primary_geo"`
	PrimaryIP         string    `json:"primary_ip"`
	PrimaryDevice     string    `json:"primary_device"`
	PrimaryOnlineTime time.Time `json:"primary_online_time"`
	AuthLogs          []AuthLog `json:"authLogs,omitempty"`
}

type UserEvent = AuthLog
