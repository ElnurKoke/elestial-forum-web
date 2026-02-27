package handler

import (
	"fmt"
	"forum/internal/models"
	"io"
	"strings"
)

type ByCreatedAt []models.Post

func (a ByCreatedAt) Len() int           { return len(a) }
func (a ByCreatedAt) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCreatedAt) Less(i, j int) bool { return a[i].CreateAt.After(a[j].CreateAt) }

type ByCreatedAtMes []models.Message

func (a ByCreatedAtMes) Len() int      { return len(a) }
func (a ByCreatedAtMes) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (a ByCreatedAtMes) Less(i, j int) bool {
	return a[i].CreateAt.After(a[j].CreateAt)
}

type ByCreatedAtCom []models.Comment

func (a ByCreatedAtCom) Len() int           { return len(a) }
func (a ByCreatedAtCom) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCreatedAtCom) Less(i, j int) bool { return a[i].Created_at.After(a[j].Created_at) }

var imageSignatures = map[string]string{
	"\xFF\xD8\xFF":                     ".jpg", // JPEG
	"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": ".png", // PNG
	"\x47\x49\x46\x38\x37\x61":         ".gif", // GIF87a
	"\x47\x49\x46\x38\x39\x61":         ".gif", // GIF89a
}

func checkImageSignature(file io.Reader) (string, error) {
	// Считываем начальный заголовок
	header := make([]byte, 8)
	_, err := file.Read(header)
	if err != nil {
		return "", err
	}

	// Сброс указателя чтения в начало файла
	if _, err := file.(io.Seeker).Seek(0, 0); err != nil {
		return "", err
	}

	for signature, ext := range imageSignatures {
		if strings.HasPrefix(string(header), signature) {
			return ext, nil
		}
	}

	return "", fmt.Errorf("Invalid image file ERROR")
}
