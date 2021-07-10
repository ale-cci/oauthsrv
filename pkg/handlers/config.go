package handlers

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
	"os"
)

type Config struct {
	Database *mongo.Database
}

// Read service configuration from environment variables
func EnvConfig() (*Config, error) {
	mongoConnStr := os.Getenv("MONGO_CONNSTR")
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoConnStr))
	if err != nil {
		return nil, fmt.Errorf("Unable to read configuration from env: %v", err)
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, fmt.Errorf("Unable establish connection: %v", err)
	}

	return &Config{
		Database: client.Database(os.Getenv("DB_NAME")),
	}, nil
}

func (cnf *Config) apply(handler func(*Config, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(cnf, w, r)
	}
}
