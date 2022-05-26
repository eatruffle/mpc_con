package restorekey

type KeyMetadata struct {
	Algo                string
	MetadataPublicKey   string
	ChainCodeForThisKey []byte
}
