package handlers_test

import (
	"testing"
	"context"
	"github.com/ale-cci/oauthsrv/handlers"
)


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
}


