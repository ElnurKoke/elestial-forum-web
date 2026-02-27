package handler

import (
	"context"
	_ "embed"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed ratelim.lua
var luaScript string

var script = redis.NewScript(luaScript)

type Rule struct {
	Key    string
	Limit  int
	Window time.Duration
}

func (h *Handler) CheckAtomic(rdb *redis.Client, rules []Rule) (bool, error) {
	ctx := context.Background()

	keys := make([]string, 0, len(rules))
	args := make([]interface{}, 0, len(rules)*2)

	for _, r := range rules {
		keys = append(keys, r.Key)
		args = append(args, r.Limit, int(r.Window.Seconds()))
	}

	res, err := script.Run(ctx, rdb, keys, args...).Int()
	if err != nil {
		return false, err
	}

	return res == 1, nil
}
