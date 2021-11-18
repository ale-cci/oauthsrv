package handlers_test

import (
	"context"
	"github.com/ale-cci/oauthsrv/pkg/handlers"
	"log"
	"os"
	"testing"
)

func init() {
	os.Setenv("DB_NAME", "test-oidc")
	// cd to root directory for templates importing
	if err := os.Chdir("../../"); err != nil {
		panic(err)
	}

	// Cleanup test database
	cfg, err := handlers.EnvConfig()
	if err != nil {
		log.Fatalf("Unable to get env-config: %v", err)
	}
	cfg.Database.Drop(context.Background())
}

func TestEnvConfig(t *testing.T) {
	t.Run("Should have valid database connection field", func(t *testing.T) {
		cfg, err := handlers.EnvConfig()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := cfg.Database.Client().Ping(context.TODO(), nil); err != nil {
			t.Errorf("Invalid mongo connection: %v", err)
		}
	})

	t.Run("should connect to test database", func(t *testing.T) {
		cfg, err := handlers.EnvConfig()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		want := "test-oidc"
		got := cfg.Database.Name()
		if got != want {
			t.Fatalf("want %s, got: %s", want, got)
		}
	})
}
