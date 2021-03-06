package config

import (
	"encoding/json"
	"log"
	"os"
)

var (
	singleton *Configuration
)

type Configuration struct {
	RabbitMq struct {
		Url        string
		Routingkey string
		Exchange   string
	}
	Device string
}

func init() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal("no config", err)
	}

	defer file.Close()
	decoder := json.NewDecoder(file)
	singleton = &Configuration{}
	err = decoder.Decode(singleton)
	if err != nil {
		log.Fatal("config invalid", err)
	}
}

func GetInstance() *Configuration {
	return singleton
}
