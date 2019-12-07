package config

type Log struct {
	Level string
}

type LDAP struct {
	Addr string
	Root string
	Data string
}

type Config struct {
	Log  Log
	LDAP LDAP
}

func New() *Config {
	return &Config{}
}
