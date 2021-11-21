/**
 * Package to manage application configuration/settings
 */
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/ale-cci/oauthsrv/pkg/keystore"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

/**
 * Application configuration, injected to each handlers registered.
 */
type Config struct {
	// open connection to the mongo database
	Database *mongo.Database

	// application keystore, used to sign jwts
	Keystore keystore.Keystore
}

/**
 * Generate `Config` data structure using environment variables
 */
func EnvConfig() (*Config, error) {
	mongoConnStr := os.Getenv("MONGO_CONNSTR")
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoConnStr))
	if err != nil {
		return nil, fmt.Errorf("Unable to read configuration from env: %v", err)
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, fmt.Errorf("Unable establish connection: %v", err)
	}

	ks, _ := keystore.NewTempKeystore()

	return &Config{
		Database: client.Database(os.Getenv("DB_NAME")),
		Keystore: ks,
	}, nil
}

/**
 * Inject the configuration to a custom handler function,
 * returning a standard `http.HandlerFunc`
 */
func (cnf *Config) apply(handler func(*Config, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(cnf, w, r)
	}
}
