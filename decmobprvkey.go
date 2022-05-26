package restorekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
)
import "crypto/pbkdf2"

/*
def decrypt_mobile_private_key(recovery_password, user_id, encrypted_key):
    wrap_key = hashlib.pbkdf2_hmac("sha1", recovery_password, user_id, 10000, 32)
    iv = bytes(chr(0) * 16, 'utf-8')
    cipher = AES.new(wrap_key, AES.MODE_CBC, iv)
    prv_key = _unpad(cipher.decrypt(encrypted_key))
    return prv_key
*/
func DecryptMobilePrivateKey(passphrase []byte, userId []byte, encryptedKey []byte) []byte {

	wrapKey := pbkdf2.Key(passphrase, userId, 10000, 32, sha1.New)

	iv := []byte("00000000000000000000000000000000")

	block, err := aes.NewCipher(wrapKey)

	if err != nil {
		fmt.Println("Error in block create")
	}
	cbc := cipher.NewCBCDecrypter(block, iv)

	var destKey []byte
	cbc.CryptBlocks(destKey, encryptedKey)

	return destKey
}
