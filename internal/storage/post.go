package storage

import (
	"database/sql"
	"fmt"
	"forum/internal/models"
	"os"
	"strings"
)

type PostIR interface {
	CreatePost(post models.Post) error
	GetPostByID(id int) (models.Post, error)
	GetAllPosts() ([]models.Post, error)
	Category() ([]models.Category, error)
	AddCategory(name string) error
	DeleteCategory(name string) error
	GetAllPostsByCategories(category string) ([]models.Post, error)
	GetMyPost(id int) ([]models.Post, error)
	GetMyLikedPost(id int) ([]models.Post, error)
	GetAllWaitPosts() ([]models.Post, error)
	DeletePost(id int) error
	UpdatePost(post models.Post) error
}

type PostStorage struct {
	db *sql.DB
}

func NewPostStorage(db *sql.DB) PostIR {
	return &PostStorage{
		db: db,
	}
}

func (p *PostStorage) DeletePost(id int) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	post, err := p.GetPostByID(id)
	err = os.Remove("./front/static/data/" + post.Image)
	if err != nil {
		return err
	}

	queryLikesPost := `DELETE FROM likesPost WHERE postId = $1;`
	_, err = tx.Exec(queryLikesPost, id)
	if err != nil {
		return err
	}

	rows, err := tx.Query("SELECT id FROM comment WHERE id_post = $1;", id)
	if err != nil {
		return err
	}

	for rows.Next() {
		var commentID int
		if err := rows.Scan(&commentID); err != nil {
			return err
		}
		_, err := tx.Exec("DELETE FROM likesComment WHERE commentsId = $1;", commentID)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec("DELETE FROM comment WHERE id_post = $1;", id)
	if err != nil {
		return err
	}

	_, err = tx.Exec("DELETE FROM post WHERE id = $1;", id)
	if err != nil {
		return err
	}

	return nil
}

func (p *PostStorage) GetAllPosts() ([]models.Post, error) {
	posts := []models.Post{}
	query := `
		SELECT post.id, user.username, post.title, post.description, post.imageURL, post.likes, post.dislikes, post.category, post.created_at
		FROM post
		LEFT JOIN user ON post.author_id = user.id
		WHERE post.status = "done"
		ORDER BY post.created_at DESC LIMIT 20;`
	row, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("storage: get all posts: %w", err)
	}
	for row.Next() {
		var post models.Post
		var categoriesStr string
		if err := row.Scan(&post.Id, &post.Author, &post.Title, &post.Description, &post.Image, &post.Likes, &post.Likes, &categoriesStr, &post.CreateAt); err != nil {
			return nil, fmt.Errorf("storage: get all posts: %w", err)
		}
		post.Category = strings.Split(categoriesStr, ", ")

		posts = append(posts, post)
	}

	return posts, nil
}

func (p *PostStorage) GetAllWaitPosts() ([]models.Post, error) {
	posts := []models.Post{}
	query := `
		SELECT post.id, user.username, post.title, post.description, post.imageURL, post.likes, post.dislikes, post.category, post.created_at
		FROM post
		LEFT JOIN user ON post.author_id = user.id
		WHERE post.status = "waiting"
		ORDER BY post.created_at ASC LIMIT 20;`
	row, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("storage: get all posts: %w", err)
	}
	for row.Next() {
		var post models.Post
		var categoriesStr string
		if err := row.Scan(&post.Id, &post.Author, &post.Title, &post.Description, &post.Image, &post.Likes, &post.Likes, &categoriesStr, &post.CreateAt); err != nil {
			return nil, fmt.Errorf("storage: get all posts: %w", err)
		}
		post.Category = strings.Split(categoriesStr, ", ")

		posts = append(posts, post)
	}

	return posts, nil
}

func (p *PostStorage) CreatePost(post models.Post) error {
	query := `INSERT INTO post(title, description,imageURL, author_id, category) VALUES ($1, $2, $3, $4, $5);`
	var categoriesStr string
	if len(post.Category) == 1 {
		categoriesStr = post.Category[0]
	} else {
		post.Category = uniqueStrings(post.Category)
		categoriesStr = strings.Join(post.Category, ", ")
	}

	_, err := p.db.Exec(query, post.Title, post.Description, post.Image, post.UserId, categoriesStr)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostStorage) UpdatePost(post models.Post) error {
	query := `UPDATE post SET title = $1, description = $2, category = $3 WHERE id = $4;`
	var categoriesStr string
	if len(post.Category) == 1 {
		categoriesStr = post.Category[0]
	} else {
		post.Category = uniqueStrings(post.Category)
		categoriesStr = strings.Join(post.Category, ", ")
	}

	_, err := p.db.Exec(query, post.Title, post.Description, categoriesStr, post.Id)
	if err != nil {
		return err
	}

	return nil
}

func uniqueStrings(input []string) []string {
	uniqueMap := make(map[string]struct{})
	for _, str := range input {
		uniqueMap[str] = struct{}{}
	}
	uniqueStrings := make([]string, 0, len(uniqueMap))
	for str := range uniqueMap {
		uniqueStrings = append(uniqueStrings, str)
	}
	return uniqueStrings
}

func (p *PostStorage) GetPostByID(id int) (models.Post, error) {
	query := `SELECT post.id,
			post.author_id, 
			user.username, 
			post.title, 
			post.description, 
			post.imageURL, 
			post.created_at, 
			post.likes, 
			post.dislikes ,
			post.category,
			post.status
		FROM post
		LEFT JOIN user 
		ON post.author_id = user.id
		WHERE post.id = $1;`
	row := p.db.QueryRow(query, id)
	var post models.Post
	var categoriesStr string
	if err := row.Scan(&post.Id, &post.UserId, &post.Author, &post.Title, &post.Description,
		&post.Image, &post.CreateAt, &post.Likes, &post.Dislikes, &categoriesStr, &post.Status); err != nil {
		return models.Post{}, err
	}
	post.Category = strings.Split(categoriesStr, ", ")
	return post, nil
}

func (p *PostStorage) GetMyPost(id int) ([]models.Post, error) {
	posts := []models.Post{}
	query := `SELECT 
		p.id,
		u.username,
		p.title,
		p.description,
		p.imageURL,
		p.likes,
		p.dislikes,
		p.category,
		p.created_at
	FROM 
		post p
	LEFT JOIN 
		user u
	ON
		u.id = p.author_id
	where 
		u.id = $1`
	row, err := p.db.Query(query, id)
	if err != nil {
		return nil, fmt.Errorf("storage: get my all posts: %w", err)
	}
	for row.Next() {
		var post models.Post
		var categoriesStr string
		if err := row.Scan(&post.Id, &post.Author, &post.Title, &post.Description, &post.Image, &post.Likes, &post.Likes, &categoriesStr, &post.CreateAt); err != nil {
			return nil, fmt.Errorf("storage: get all my posts: %w", err)
		}
		post.Category = strings.Split(categoriesStr, ", ")
		posts = append(posts, post)
	}

	return posts, nil
}

func (p *PostStorage) GetMyLikedPost(id int) ([]models.Post, error) {
	posts := []models.Post{}
	query := `SELECT 
		p.id,
		u.username,
		p.title,
		p.description,
		p.imageURL,
		p.likes,
		p.dislikes,
		p.category,
		p.created_at
	FROM 
		post p
	LEFT JOIN
		user u
	ON
		u.id = p.author_id
	JOIN 
		likesPost lp
	ON
		lp.postId = p.id
	WHERE  
		lp.userId = $1 AND lp.like1 = 1 AND p.status = "done";`
	row, err := p.db.Query(query, id)
	if err != nil {
		return nil, fmt.Errorf("storage: get all liked posts: %w", err)
	}
	for row.Next() {
		var post models.Post
		var categoriesStr string
		if err := row.Scan(&post.Id, &post.Author, &post.Title, &post.Description, &post.Image, &post.Likes, &post.Likes, &categoriesStr, &post.CreateAt); err != nil {
			return nil, fmt.Errorf("storage: get all liked posts: %w", err)
		}
		post.Category = strings.Split(categoriesStr, ", ")

		posts = append(posts, post)
	}

	return posts, nil
}
