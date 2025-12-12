package session

import "time"

type session struct {
	username string
	expire   time.Time
}

func (s *session) isExpired() bool {
	return s.expire.Before(time.Now())
}

var sessions = map[string]session{}
