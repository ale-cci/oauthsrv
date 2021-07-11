package jwt

type PrivateKeystore interface {
	GetPrivateKey(kid string) (interface{}, error)
}

type PublicKeystore interface {
	GetPublicKey(kid string) (interface{}, error)
}
