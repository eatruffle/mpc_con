package restorekey

type Mobile struct {
	EncryptedKey string `json:"encryptedKey"`
	KeyId        string `json:"keyId"`
	DeviceId     string `json:"deviceId"`
	UserId       string `json:"userId"`
}
