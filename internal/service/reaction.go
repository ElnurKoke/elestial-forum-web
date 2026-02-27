package service

import (
	"forum/internal/models"
	"forum/internal/storage"
)

type EmotionServiceIR interface {
	CreateOrUpdateEmotionComment(models.Like) (error, bool)
	CreateOrUpdateEmotionPost(models.Like) (error, bool)
}

type EmotionService struct {
	storage storage.ReactionIR
}

func NewEmotionService(storage storage.ReactionIR) EmotionServiceIR {
	return &EmotionService{
		storage,
	}
}

func (e *EmotionService) CreateOrUpdateEmotionPost(postEmo models.Like) (error, bool) {
	exists1, err := e.storage.EmotionPostExistsFull(postEmo)
	if err != nil {
		return err, true
	}
	existEmo := false
	if exists1 {
		existEmo = true
		postEmo.Islike = -1
		return e.storage.UpdateEmotionPost(postEmo), true
	}

	exists, err := e.storage.EmotionPostExists(postEmo.PostID, postEmo.UserID)
	if err != nil {
		return err, true
	}
	if exists {
		err = e.storage.UpdateEmotionPost(postEmo)
		if err != nil {
			return err, true
		}
	} else {
		err = e.storage.CreateEmotionPost(postEmo)
		if err != nil {
			return err, true
		}
	}

	return nil, existEmo
}

func (e *EmotionService) CreateOrUpdateEmotionComment(commentEmo models.Like) (error, bool) {
	exists1, err := e.storage.EmotionCommentExistsFull(commentEmo)
	if err != nil {
		return err, true
	}
	existEmo := false
	if exists1 {
		existEmo = true
		commentEmo.Islike = -1
		return e.storage.UpdateEmotionComment(commentEmo), true
	}

	exists, err := e.storage.EmotionCommentExists(commentEmo.CommentID, commentEmo.UserID)
	if err != nil {
		return err, true
	}
	if exists {
		err = e.storage.UpdateEmotionComment(commentEmo)
		if err != nil {
			return err, true
		}
	} else {
		err = e.storage.CreateEmotionComment(commentEmo)
		if err != nil {
			return err, true
		}
	}

	return nil, existEmo
}
