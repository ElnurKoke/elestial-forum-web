package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"forum/internal/models"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

func (h *Handler) updateRiskLevelByLogsAsync(userID int, assessment models.RiskAssessment) {
	go func() {
		assessment.UserID = userID
		logs := assessment.AuthLogs
		if len(logs) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()

		newAssessment, err := callLLM(ctx, assessment, h.Config.LLM.APIURL)
		if err != nil {
			log.Println("callLLM:", err)
			assessment.RiskLevel = detectRiskLevelByLogs(logs, assessment)
			newAssessment = assessment
		} else {
			merged := assessment
			if newAssessment.RiskLevel != "" {
				merged.RiskLevel = newAssessment.RiskLevel
			}
			if newAssessment.Reason != "" {
				merged.Reason = newAssessment.Reason
			}
			newAssessment = merged
		}

		if riskPriority(newAssessment.RiskLevel) > riskPriority(assessment.RiskLevel) {
			log.Println("risk escalated:", assessment.RiskLevel, "→", newAssessment.RiskLevel)

			if err := h.Service.DeleteTokenByUserID(userID); err != nil {
				log.Println("delete token error:", err)
			} else {
				log.Println("user token deleted due to risk escalation")
			}
		}

		if err := h.Service.UpdateRiskAssessment(newAssessment); err != nil {
			log.Println("risk update error:", err)
			return
		}
		log.Println("risk level updated:", newAssessment)
	}()
}

func detectRiskLevelByLogs(logs []models.AuthLog, assessment models.RiskAssessment) string {
	recent := logs
	if len(recent) > 10 {
		recent = recent[:10]
	}

	failCount := 0
	consecutiveFails := 0
	maxConsecutiveFails := 0
	for _, lg := range recent {
		if !lg.Status {
			failCount++
			consecutiveFails++
			if consecutiveFails > maxConsecutiveFails {
				maxConsecutiveFails = consecutiveFails
			}
			continue
		}
		consecutiveFails = 0
	}

	latest := recent[0]
	suspiciousSource := assessment.PrimaryIP != "" &&
		latest.IP != "" &&
		assessment.PrimaryIP != latest.IP
	suspiciousDevice := assessment.PrimaryDevice != "" &&
		latest.Device != "" &&
		assessment.PrimaryDevice != latest.Device

	switch {
	case failCount >= 5 || maxConsecutiveFails >= 3:
		return "RED"
	case failCount >= 2 || suspiciousSource || suspiciousDevice:
		return "YELLOW"
	default:
		return "GREEN"
	}
}

func riskPriority(level string) int {
	switch level {
	case "GREEN":
		return 1
	case "YELLOW":
		return 2
	case "RED":
		return 3
	default:
		return 0
	}
}

type ollamaGenerateResp struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error"`
}

type llmMini struct {
	RiskLevel string `json:"risk_level"`
	Reason    string `json:"reason"`
}

func callLLM(ctx context.Context, r models.RiskAssessment, apiURL string) (models.RiskAssessment, error) {
	if strings.TrimSpace(apiURL) == "" {
		return models.RiskAssessment{}, errors.New("llm api url is not configured")
	}
	logs := r.AuthLogs
	if len(logs) > 10 {
		logs = logs[:10]
	}

	b, _ := json.Marshal(logs)

	prompt := `
Evaluate authentication risk using logs and current login data.
Return ONLY valid JSON (no extra text):
{"risk_level":"GREEN|YELLOW|RED","reason":"short technical reason"}
Use highest detected severity. If insufficient data -> YELLOW.
Primary IP: ` + r.PrimaryIP + `
Primary Device: ` + r.PrimaryDevice + `
Primary Geo: ` + r.PrimaryGeo + `
Logs: ` + string(b)

	payload := map[string]interface{}{
		"model":  "mistral",
		"prompt": prompt,
		"stream": false,
	}

	body, _ := json.Marshal(payload)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		apiURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		return models.RiskAssessment{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return models.RiskAssessment{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return models.RiskAssessment{}, errors.New("ollama http status: " + resp.Status + " body: " + string(raw))
	}

	var gr ollamaGenerateResp
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return models.RiskAssessment{}, err
	}
	if gr.Error != "" {
		return models.RiskAssessment{}, errors.New("ollama error: " + gr.Error)
	}

	txt := strings.TrimSpace(gr.Response)
	if txt == "" {
		return models.RiskAssessment{}, errors.New("ollama empty response")
	}

	start := strings.IndexByte(txt, '{')
	end := strings.LastIndexByte(txt, '}')
	if start == -1 || end == -1 || end <= start {
		return models.RiskAssessment{}, errors.New("llm returned non-json: " + txt)
	}
	jsonPart := txt[start : end+1]

	var mini llmMini
	if err := json.Unmarshal([]byte(jsonPart), &mini); err != nil {
		return models.RiskAssessment{}, errors.New("bad json from llm: " + err.Error() + " raw: " + jsonPart)
	}

	mini.RiskLevel = strings.ToUpper(strings.TrimSpace(mini.RiskLevel))
	mini.Reason = strings.TrimSpace(mini.Reason)

	if mini.RiskLevel != "GREEN" && mini.RiskLevel != "YELLOW" && mini.RiskLevel != "RED" {
		return models.RiskAssessment{}, errors.New("invalid risk_level from llm: " + mini.RiskLevel)
	}
	if mini.Reason == "" {
		return models.RiskAssessment{}, errors.New("empty reason from llm")
	}

	return models.RiskAssessment{
		RiskLevel: mini.RiskLevel,
		Reason:    mini.Reason,
	}, nil
}
