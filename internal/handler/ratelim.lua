-- atomic rate limit script

for i = 1, #KEYS do
    local current = tonumber(redis.call("GET", KEYS[i]) or "0")
    local limit = tonumber(ARGV[(i - 1) * 2 + 1])

    if current >= limit then
        return 0
    end
end

for i = 1, #KEYS do
    local count = redis.call("INCR", KEYS[i])
    local ttl = tonumber(ARGV[(i - 1) * 2 + 2])

    if count == 1 then
        redis.call("EXPIRE", KEYS[i], ttl)
    end
end

return 1
