package restorekey

type Metadata struct {
	ChainCode string `json:"chainCode"`
	Keys      []Key  `json:"keys"`
	TenantId  string `json:"tenantId"`
}

type Keys struct {
	Key Key `json:"067681f4-3ae7-eda5-9ab7-4a3cc96c110a"`
}

type Key struct {
	ChainCode string `json:"chainCode"`
	KeyId     string `json:"keyId"`
	Algo      string `json:"algo"`
	PubKey    string `json:"publicKey"`
}
