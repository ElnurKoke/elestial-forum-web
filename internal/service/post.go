package service

import (
	"fmt"
	"forum/internal/models"
	"forum/internal/storage"
	"strings"
)

type ServicePostIR interface {
	CreatePost(post models.Post) error
	GetPostId(id int) (models.Post, error)
	GetAllPosts() ([]models.Post, error)
	GetCategories() ([]models.Category, error)
	AddCategory(name string) error
	DeleteCategory(name string) error

	GetAllPostsByCategories(category string) ([]models.Post, error)
	GetMyPost(int) ([]models.Post, error)
	GetMyLikePost(int) ([]models.Post, error)
	GetAllWaitPosts() ([]models.Post, error)

	DeletePost(id int) error
	UpdatePost(post models.Post) error
}

type PostService struct {
	storage storage.PostIR
}

func NewPostService(postIR storage.PostIR) ServicePostIR {
	return &PostService{
		storage: postIR,
	}
}

func (p *PostService) DeleteCategory(name string) error {
	return p.storage.DeleteCategory(name)
}

func (p *PostService) AddCategory(name string) error {
	return p.storage.AddCategory(name)
}

func (p *PostService) DeletePost(id int) error {
	return p.storage.DeletePost(id)
}

func (p *PostService) GetAllWaitPosts() ([]models.Post, error) {
	return p.storage.GetAllWaitPosts()
}

func (p *PostService) CreatePost(post models.Post) error {
	for x := range post.Category {
		post.Category[x] = strings.TrimSpace(post.Category[x])
		if len(post.Category[x]) == 0 {
			return fmt.Errorf("empty category")
		}
	}
	post.Title = strings.TrimSpace(post.Title)
	if len(post.Title) == 0 {
		return fmt.Errorf("empty title")
	}
	post.Description = strings.TrimSpace(post.Description)
	if len(post.Description) == 0 {
		return fmt.Errorf("empty Description")
	}
	if len(post.Category) == 0 {
		return fmt.Errorf("INVALID CATEGORY, please select existing categories ")
	}
	for _, category := range post.Category {
		if len(category) == 0 || len(category) >= 40 {
			return fmt.Errorf("INVALID CATEGORY, category should be shorter than 35 symbols and not empty")

		}
	}
	if len(post.Description) > 600 || len(post.Description) == 0 {
		return fmt.Errorf("description should be shorter than 400 symbols and not empty")

	}
	if len(post.Title) == 0 || len(post.Title) >= 80 {
		return fmt.Errorf("INVALID TITLE, title should be shorter than 35 symbols and not empty")

	}

	return p.storage.CreatePost(post)
}
func (p *PostService) UpdatePost(post models.Post) error {
	return p.storage.UpdatePost(post)
}

func (p *PostService) GetPostId(id int) (models.Post, error) {
	return p.storage.GetPostByID(id)
}

func (p *PostService) GetAllPosts() ([]models.Post, error) {
	return p.storage.GetAllPosts()
}

func (p *PostService) GetCategories() ([]models.Category, error) {
	return p.storage.Category()
}

func (p *PostService) GetAllPostsByCategories(category string) ([]models.Post, error) {
	return p.storage.GetAllPostsByCategories(category)
}

func (p *PostService) GetMyPost(id int) ([]models.Post, error) {
	return p.storage.GetMyPost(id)
}

func (p *PostService) GetMyLikePost(id int) ([]models.Post, error) {
	return p.storage.GetMyLikedPost(id)
}
