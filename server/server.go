package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"gopkg.in/yaml.v2"
)


type Token struct {
	token  string
	expire int64
}

type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
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
	Exp int `json:"exp"`
	ClientId string `json:"client_id"`
}

type ServerConfig struct {
	Effective int `yaml:"effective"`
	Coexist   int `yaml:"coexist"`
}

type ClientConfig struct {
	Id     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type OauthConfig struct {
	Server ServerConfig `yaml:"server"`
	Client ClientConfig `yaml:"client"`
}

// 旧token
// 在当前token生效时仍可能生效
// 示例如下：     effective
// oldToken: |<==============>|
//    token:          |<==============>|
//          coexist-> |<~~~~~>|
//           ------------------------->
//                       ^
//                      now
// effective 为token生效的时间（图例：<=====>）
// coexist   为中间这段重合时间（图例：<~~~~~>）
var oldToken Token
// 当前生效token
var token Token
var coexist int = 5
var effective int = 300
var clientId string = "client"
var clientSecret string = "123456"


/**
 * 获取新的token
 * 允许5秒时延
 */
func getToken() Token {
	if (Token{} == token) {
		token = initToken()
	}
	now := time.Now().Unix()
	if now > token.expire-int64(coexist) {
		oldToken = token
		token = initToken()
		return token
	}
	return token
}

/**
 * 初始化token
 */
 func initToken() Token {
	now := time.Now().Unix()
	expire := now + int64(effective)
	originData := "1" + strconv.Itoa(int(now))
	token := md5.Sum([]byte(originData))
	return Token{token: fmt.Sprintf("%x", token), expire: expire}
}

func getAccessToken() AccessToken {
	getToken()
	vo := AccessToken{
		AccessToken: token.token, 
		TokenType: "bearer", 
		ExpiresIn: int(token.expire - time.Now().Unix()),
		Scope: "app",
	}
	return vo
}

func initError(path string) Error {
	return Error{
		Status: 401,
		Error: "Unauthorized",
		Message: "Unauthorized",
		Path: path,
		Timestamp: time.Now(),
	}
}

/**
 * 获取token接口
 */
func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth();
	if (!ok || u != clientId || p != clientSecret) {
		write(initError("/oauth/token"), w)
		return
	}
  write(getAccessToken(), w)
}

func isExpire(t Token) bool {
	if (t.expire < time.Now().Unix()) {
		return true
	}
	return false
}

/**
 * token验证
 */
func checkTokenHandler(w http.ResponseWriter, r *http.Request) {
	requestTokenStr := r.URL.Query().Get("token")
	if (requestTokenStr == "") {
		r.ParseForm()
		requestTokenStr = r.Form.Get("token")
	}
	fmt.Println(requestTokenStr)
	u, p, ok := r.BasicAuth();
	if (!ok || u != clientId || p != clientSecret) {
		// basic 验证
		write(initError("/oauth/check_token"), w)
		return
	}
	var requestToken Token
	if (requestTokenStr == "") {
		write(CheckError{Error: "invalid_token", ErrorDescription: "Token was not recognised"}, w)
		return
	}
	if (requestTokenStr == token.token) {
		requestToken = token
	} else if (requestTokenStr == oldToken.token) {
		requestToken = oldToken
	} else {
		write(CheckError{Error: "invalid_token", ErrorDescription: "Token was not recognised"}, w)
		return
	}
	if (isExpire(requestToken)) {
		write(CheckError{Error: "invalid_token", ErrorDescription: "Token has expired"}, w)
		return
	}
	write(CheckResult{
		Scope: []string{"app"},
		Active: true,
		Exp: int(requestToken.expire - time.Now().Unix()),
		ClientId: u,
	}, w)
}

/**
 * 写回客户端（响应）
 */
func write(data interface{}, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json, _ := json.Marshal(data)
	w.Write(json)
}

/**
 * 重新加载配置
 */
 func reloadConfigHandler(w http.ResponseWriter, r *http.Request) {
	loadConfig()
  write("success", w)
}

/**
 * 加载配置文件
 */
func loadConfig() {
	content, err := ioutil.ReadFile("properties.yml")
	if err != nil {
		log.Println("config load error: ", err.Error())
		return
	}
	config := &OauthConfig{}
	yaml.Unmarshal(content, &config)
	configEffective := (*config).Server.Effective
	configCoexist := (*config).Server.Coexist
	if (configEffective < configCoexist) {
		log.Println("config load error: coexist > effective")
		return
	}
	if (configEffective - configCoexist < configCoexist) {
		log.Println("config load error: coexist > effective - coexist")
		return
	}
	effective = configEffective
	coexist = configCoexist
	clientId = (*config).Client.Id
	clientSecret = (*config).Client.Secret
	log.Println("load config success")
}

func main()  {
	loadConfig()
	http.HandleFunc("/oauth/token", getTokenHandler)
	http.HandleFunc("/oauth/check_token", checkTokenHandler)
	http.HandleFunc("/oauth/reload_config", reloadConfigHandler)
	http.ListenAndServe(":9800", nil)
}