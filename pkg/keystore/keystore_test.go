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

	t.Run("Should be able to retrieve public key for generated key", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		pkInfo, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		pubKey, err := ks.PublicKey(pkInfo.KeyID)

		assert.NilError(t, err)
		assert.Check(t, pubKey == &pkInfo.PrivateKey.PublicKey)
	})

	t.Run("should be able to retrieve private key", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		pkInfo, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		privKey, err := ks.PrivateKey(pkInfo.KeyID)
		assert.NilError(t, err)

		assert.Check(t, privKey == pkInfo.PrivateKey)
	})
}
