package main

import "time"

type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type Token struct {
	token  string
	expire int64
}

type Error struct {
	Timestamp time.Time `json:"timestamp"`
	Status int `json:"status"`
	Error string `json:"error"`
	Message string `json:"message"`
	Path string `json:"path"`
}

type CheckError struct {
	Error string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type CheckResult struct {
	Scope []string `json:"scope"`
	Active bool `json:"active"`
	Exp int64 `json:"exp"`
	ClientId string `json:"client_id"`
}

type ServerConfig struct {
	Effective int `yaml:"effective"`
	Coexist   int `yaml:"coexist"`
	GracePeriod int64 `yaml:"gracePeriod"`
	Port string `yaml:"port"`
}

type ClientConfig struct {
	Id     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type OauthConfig struct {
	Server ServerConfig `yaml:"server"`
	Client ClientConfig `yaml:"client"`
}