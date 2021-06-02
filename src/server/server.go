package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func initError(path string) Error {
	return Error{
		Status:    401,
		Error:     "Unauthorized",
		Message:   "Unauthorized",
		Path:      path,
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
  write(GetAccessToken(), w)
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
	log.Println(requestTokenStr)
	u, p, ok := r.BasicAuth();
	if (!ok || u != clientId || p != clientSecret) {
		// basic 验证
		write(initError("/oauth/check_token"), w)
		return
	}
	result := CheckToken(requestTokenStr)
	write(result, w)
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
	result := "success"
	if !LoadConfig() {
		result = "failed"
	}
  write(result, w)
}

func main()  {
	LoadConfig()
	http.HandleFunc("/oauth/token", getTokenHandler)
	http.HandleFunc("/oauth/check_token", checkTokenHandler)
	http.HandleFunc("/oauth/reload_config", reloadConfigHandler)
	log.Printf("server initialized with port %s\n", port)
	http.ListenAndServe(":" + port, nil)
}