package auth

import (
	"time"

	"github.com/go-redis/redis"
	"github.com/jpillora/backoff"
)

var boff = &backoff.Backoff{
	Min:    2 * time.Microsecond,
	Max:    100 * time.Microsecond,
	Jitter: true,
}

// RedisClient is an interface of redis.Client so that we can mock it in our tests
type RedisClient interface {
	Del(keys ...string) *redis.IntCmd
	Get(key string) *redis.StringCmd
	Set(key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

// storageGet retreives a value for the specified key
func storageGet(storage RedisClient, key string) (res string, err error) {
	for c := 0; c < 3; c++ {
		res, err = storage.Get(key).Result()

		if err != nil {
			time.Sleep(boff.Duration())
			continue
		}
		break
	}
	boff.Reset()

	return res, err
}

// storageSet inserts the store object into the cache for the specified key
func storageSet(storage RedisClient, key string, obj interface{}, ttl time.Duration) (err error) {
	for c := 0; c < 3; c++ {
		if err = storage.Set(key, obj, ttl).Err(); err != nil {
			time.Sleep(boff.Duration())
			continue
		}
		break
	}
	boff.Reset()

	return err
}

// storageDelete deletes the store object from the cache for a specified key
func storageDelete(storage RedisClient, key string) (err error) {
	for c := 0; c < 3; c++ {
		if err = storage.Del(key).Err(); err != nil {
			time.Sleep(boff.Duration())
			continue
		}
		break
	}
	boff.Reset()

	return err
}

// storageGetAndDelete retreives a value for the specified key and upon finding, deletes.
func storageGetAndDelete(storage RedisClient, key string) (string, error) {
	item, err := storageGet(storage, key)

	go storageDelete(storage, key)

	return item, err
}
