package storage

import (
	"database/sql"
	"fmt"
	"forum/internal/models"
	"log"
)

type CommentIR interface {
	CreateComment(id, author_id int, comment string) (int, error)
	GetCommentsByIdPost(id int) ([]models.Comment, error)
	DeleteComment(id int) error
	GetCommentsByIdComment(id int) (models.Comment, error)
	UpdateComment(comment models.Comment) error
}

type CommentStorage struct {
	db *sql.DB
}

func newCommentStorage(db *sql.DB) CommentIR {
	return &CommentStorage{
		db: db,
	}
}

func (p *CommentStorage) UpdateComment(comment models.Comment) error {
	query := `UPDATE comment SET comment = $1 WHERE id = $2;`

	_, err := p.db.Exec(query, comment.Text, comment.Id)
	if err != nil {
		return err
	}

	return nil
}

func (p *CommentStorage) DeleteComment(id int) error {
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
	_, err = tx.Exec("DELETE FROM likesComment WHERE commentsId = $1;", id)
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM comment WHERE id = $1;", id)
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM notification WHERE comment_id = $1;", id)
	if err != nil {
		return err
	}

	return nil
}

func (c *CommentStorage) CreateComment(id, author_id int, comment string) (int, error) {
	result, err := c.db.Exec(`INSERT INTO comment(id_post, author_id, comment) VALUES (?, ?, ?)`, id, author_id, comment)
	if err != nil {
		return 0, fmt.Errorf("repo: create comment: falied %w", err)
	}
	insertedID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("repo: get last inserted ID: %w", err)
	}

	return int(insertedID), nil
}

func (c *CommentStorage) GetCommentsByIdPost(id int) ([]models.Comment, error) {
	comments := []models.Comment{}
	query := `SELECT c.id, u.username, c.comment, c.likes, c.dislikes, c.created_at 
		FROM comment c
		LEFT JOIN user u
		ON u.id = c.author_id
		WHERE c.id_post=$1`
	rows, err := c.db.Query(query, id)
	if err != nil {
		return nil, fmt.Errorf("storage: comment by id post: %w", err)
	}
	for rows.Next() {
		var comment models.Comment
		if err := rows.Scan(&comment.Id, &comment.Creator, &comment.Text, &comment.Likes, &comment.Dislikes, &comment.Created_at); err != nil {
			log.Println(err.Error())
			return nil, fmt.Errorf("storage: comment by id post: %w", err)
		}
		comments = append(comments, comment)
	}
	return comments, err
}

func (c *CommentStorage) GetCommentsByIdComment(id int) (models.Comment, error) {
	query := `SELECT c.id_post,c.author_id, u.username, c.comment, c.likes, c.dislikes, c.created_at 
		FROM comment c
		LEFT JOIN user u
		ON u.id = c.author_id
		WHERE c.id = $1`
	row := c.db.QueryRow(query, id)
	var comment models.Comment
	if err := row.Scan(&comment.PostId, &comment.UserId, &comment.Creator, &comment.Text, &comment.Likes, &comment.Dislikes, &comment.Created_at); err != nil {
		log.Println(err.Error())
		return models.Comment{}, fmt.Errorf("storage: comment by id comment: %w", err)
	}
	comment.IsAuth = true
	comment.Id = id
	return comment, nil
}
