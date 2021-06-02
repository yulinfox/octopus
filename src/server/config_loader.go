package main

import (
	"io/ioutil"
	"log"
	"time"

	"gopkg.in/yaml.v2"
)

/**
 * 加载配置文件
 */
 func LoadConfig() bool {
	content, err := ioutil.ReadFile("properties.yml")
	if err != nil {
		log.Println("config load error: ", err.Error())
		return false
	}
	config := &OauthConfig{}
	yaml.Unmarshal(content, &config)
	configEffective := (*config).Server.Effective
	configCoexist := (*config).Server.Coexist
	gracePeriod := (*config).Server.GracePeriod
	port = (*config).Server.Port
	if port == "" {
		port = "9800"
	}
	if (gracePeriod > 0) {
		ignoreEndTime = time.Now().Unix() + gracePeriod
	}
	if (configEffective < configCoexist) {
		log.Println("config load error: coexist > effective")
		return false
	}
	if (configEffective - configCoexist < configCoexist) {
		log.Println("config load error: coexist > effective - coexist")
		return false
	}
	effective = configEffective
	coexist = configCoexist
	clientId = (*config).Client.Id
	clientSecret = (*config).Client.Secret
	log.Println("load config success")
	return true
}