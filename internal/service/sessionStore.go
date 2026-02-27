package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

type WebAuthnSessionStore interface {
	Save(ctx context.Context, sessionID string, data *webauthn.SessionData) error
	Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
	Delete(ctx context.Context, sessionID string) error
}

type RedisWebAuthnSessionStore struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewRedisWebAuthnSessionStore(
	rdb *redis.Client,
	ttl time.Duration,
) *RedisWebAuthnSessionStore {
	return &RedisWebAuthnSessionStore{
		rdb: rdb,
		ttl: ttl,
	}
}

func (s *RedisWebAuthnSessionStore) Save(
	ctx context.Context,
	sessionID string,
	data *webauthn.SessionData,
) error {
	key := "webauthn:session:" + sessionID

	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return s.rdb.Set(ctx, key, raw, s.ttl).Err()
}

func (s *RedisWebAuthnSessionStore) Get(
	ctx context.Context,
	sessionID string,
) (*webauthn.SessionData, error) {
	key := "webauthn:session:" + sessionID

	raw, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("webauthn session not found or expired")
		}
		return nil, err
	}

	var data webauthn.SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *RedisWebAuthnSessionStore) Delete(
	ctx context.Context,
	sessionID string,
) error {
	key := "webauthn:session:" + sessionID
	return s.rdb.Del(ctx, key).Err()
}
