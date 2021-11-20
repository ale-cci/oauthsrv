package keystore_test

import (
	"testing"

	"github.com/ale-cci/oauthsrv/pkg/keystore"
	"gotest.tools/assert"
)

func TestKeystore(t *testing.T) {
	t.Run("keystore should be able to generate private key", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		pkInfo, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		assert.Check(t, pkInfo.Alg == "HS256")
		assert.Check(t, pkInfo.KeyID != "")
		assert.Check(t, pkInfo.PrivateKey != nil)
	})

}
