package main

import (
	"crypto/md5"
	"fmt"
	"log"
	"strconv"
	"time"
)

// 旧token
// 在当前token生效时仍可能生效
// 示例如下：     effective
// oldToken: |<==============>|
//    currentToken:          |<==============>|
//          coexist-> |<~~~~~>|
//           ------------------------->
//                       ^
//                      now
// effective 为token生效的时间（图例：<=====>）
// coexist   为中间这段重合时间（图例：<~~~~~>）
var oldToken Token

// 当前生效token
var currentToken Token
var coexist int = 5
var effective int = 300
var clientId string = "client"
var clientSecret string = "123456"

// 免校验时间
var ignoreEndTime int64 = 0

// 端口
var port string = "9800"

/**
 * 获取新的token
 * 允许5秒时延
 */
func getToken() Token {
	if (Token{} == currentToken) {
		currentToken = initToken()
	}
	now := time.Now().Unix()
	if now > currentToken.expire-int64(coexist) {
		oldToken = currentToken
		currentToken = initToken()
		return currentToken
	}
	return currentToken
}

/**
 * 初始化token
 */
func initToken() Token {
	now := time.Now().Unix()
	expire := now + int64(effective+coexist)
	originData := "1" + strconv.Itoa(int(now))
	currentToken := md5.Sum([]byte(originData))
	log.Printf("now is %d and current token willing expire after %d\n", now, expire)
	return Token{token: fmt.Sprintf("%x", currentToken), expire: expire}
}

func GetAccessToken() AccessToken {
	token := getToken()
	vo := AccessToken{
		AccessToken: token.token,
		TokenType:   "bearer",
		ExpiresIn:   int(token.expire-time.Now().Unix()) - coexist,
		Scope:       "app",
	}
	return vo
}

/**
* 判断token是否过期
*/
func isExpire(t Token) bool {
	if t.expire < time.Now().Unix() {
		return true
	}
	return false
}

func CheckToken(requestTokenStr string) interface{} {
	// 未传token
	if requestTokenStr == "" {
		return CheckError{Error: "invalid_token", ErrorDescription: "Token was not recognised"}
	}

	// 如果在免验证时间范围内，不做校验
	if ignoreEndTime > time.Now().Unix() {
		return CheckResult{
			Scope:    []string{"app"},
			Active:   true,
			Exp:      ignoreEndTime - time.Now().Unix(),
			ClientId: clientId,
		}
	}

	// 检查token是当前current还是old并赋值
	var requestToken Token
	if requestTokenStr == currentToken.token {
		requestToken = currentToken
	} else if requestTokenStr == oldToken.token {
		requestToken = oldToken
	} else {
		return CheckError{Error: "invalid_token", ErrorDescription: "Token was not recognised"}
	}
	// 判断token是否失效
	if isExpire(requestToken) {
		return CheckError{Error: "invalid_token", ErrorDescription: "Token has expired"}
	}
	return CheckResult{
		Scope:    []string{"app"},
		Active:   true,
		Exp:      requestToken.expire - int64(coexist) - time.Now().Unix(),
		ClientId: clientId,
	}
}
