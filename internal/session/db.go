package session

import "time"

var users = map[string]string{
	"admin": "admin",
	"q":     "q",
}

var sessions = map[string]session{}

type session struct {
	username string
	expire   time.Time
}

func (s *session) isExpired() bool {
	return s.expire.Before(time.Now())
}
