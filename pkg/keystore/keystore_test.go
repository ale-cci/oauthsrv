package keystore_test

import (
	"testing"
	"unicode"

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

	t.Run("Consecutive calls to GetSigningKey should return same key", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		fst, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		snd, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		assert.Check(t, fst.KeyID == snd.KeyID)
		assert.Check(t, fst.PrivateKey == snd.PrivateKey)
	})

	t.Run("among instantiations key ids should be different", func(t *testing.T) {
		ks1, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		key1, err := ks1.GetSigningKey("HS256")
		assert.NilError(t, err)

		ks2, err := keystore.NewTempKeystore()
		key2, err := ks2.GetSigningKey("HS256")
		assert.NilError(t, err)

		assert.Check(t, key1.KeyID != key2.KeyID)
	})

	t.Run("should return error if signing algorithm is not recognized", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		info, err := ks.GetSigningKey("HSRSA257")
		assert.Check(t, err != nil)
		assert.Check(t, info == nil)
	})

	t.Run("fetching unexistent public key should not crash the app", func(t *testing.
		T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		_, err = ks.PublicKey("random-kid")
		assert.Check(t, err != nil)
	})

	t.Run("KeyID should be all ascii-letters", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		info, err := ks.GetSigningKey("HS256")
		assert.NilError(t, err)

		for _, c := range info.KeyID {
			assert.Check(t, c <= unicode.MaxASCII)
		}
	})

	t.Run("Fetching unexistent private key should not crash the server", func(t *testing.T) {
		ks, err := keystore.NewTempKeystore()
		assert.NilError(t, err)

		_, err = ks.PrivateKey("random-kid")
		assert.Check(t, err != nil)
	})
}
