package config

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	GetConfig()
}

var (
	c *Config
)

type Config struct {
	JWT *JWT
}

type JWT struct {
	Key []byte
}

func GetConfig() *Config {
	if c == nil {

		key := os.Getenv("JWT_KEY")
		if key == "" {
			panic("JWT_KEY is not set")
		}

		c = &Config{
			JWT: &JWT{
				Key: []byte(key),
			},
		}
	}

	return c
}
