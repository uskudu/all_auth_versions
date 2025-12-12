package shared

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const JwtSecret = "qwerty"
const SessionTokenMaxAgeSeconds = 60
const JwtExpSeconds = 60
