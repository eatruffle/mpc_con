package restorekey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	//	"github.com/google/uuid"
	"io/ioutil"
	"log"
	"reflect"
	"strings"
)

func RestoreKey(zipPath string, privatePemPath string, passphrase string, keyPass string, mobileKeyPemPath string, mobileKeyPass string) map[string]PrivateKey {

	keyMetadataMapping := make(map[string]KeyMetadata)

	privateKeys := make(map[string]PrivateKey)

	//var playersData[3][3]int

	playersData := map[string]map[string]uint64{}
	//playersData["var1"] = map[string]int{}

	//	fmt.Println(m["var1"]["var2"])

	prvKeyFile, err := ioutil.ReadFile(privatePemPath)

	prvKeyPem, _ := pem.Decode(prvKeyFile)

	prvPemBytes := prvKeyPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(prvPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(prvPemBytes); err != nil { // note this returns type `interface{}`
			log.Printf("Unable to parse RSA private key, generating a temp one :%s", err.Error())
		}
	}

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Printf("Unable to parse RSA private key, generating a temp one : %s", err.Error())
	}

	zip, err := Unzip(zipPath, "./")

	fmt.Println(zip)

	metadata, err := ioutil.ReadFile("metadata.json")

	fmt.Println("Metadata ", metadata)

	var metadataObj Metadata
	err = json.Unmarshal(metadata, &metadataObj)

	if err != nil {
		log.Panic("metadataObj json parser error ", err)
	}

	defaultChainCode, err := hex.DecodeString(metadataObj.ChainCode)

	if err != nil {
		log.Panic("hex.DecodeString(metadataObj.ChainCode) ", err)
	}

	keysInBackup := metadataObj.Keys

	if keysInBackup == nil {
		//TODO extract keyId from metadata.json
		key := Key{metadataObj.ChainCode, "067681f4-3ae7-eda5-9ab7-4a3cc96c110a", "MPC_ECDSA_SECP256K1", metadataObj.Keys[0].PubKey}
		keysInBackup = append(keysInBackup, key)
	}

	var chainCodeForThisKey []byte
	for _, key := range keysInBackup {

		metadataPublicKey := key.PubKey
		algo := key.Algo

		if key.ChainCode != "" {

			chainCodeForThisKey, _ = hex.DecodeString(key.ChainCode)
		} else {
			chainCodeForThisKey = defaultChainCode
		}

		keyMetadataMapping[key.KeyId] = KeyMetadata{algo, metadataPublicKey, chainCodeForThisKey}

	}

	var cosigner_id string
	var key_id string

	for _, name := range zip {
		if strings.HasPrefix(name, "MOBILE") {
			mobile, err := ioutil.ReadFile(name)
			var mobileObj Mobile
			err = json.Unmarshal(mobile, &mobileObj)
			if err != nil {
				log.Panic("mobile json parser error ", err)
			}

			var data []byte
			if _, ok := keyMetadataMapping[mobileObj.KeyId]; ok {
				//do something here

				if passphrase == "" {
					encKey, _ := hex.DecodeString(mobileObj.EncryptedKey)

					data = DecryptMobilePrivateKey([]byte(passphrase), []byte(mobileObj.UserId), encKey)
				} else {
					mobilKeyPem, err := ioutil.ReadFile(mobileKeyPemPath)

					if err != nil {
						fmt.Println("Error in open mobile_key_pem_path")
					}

					privPem, _ := pem.Decode(mobilKeyPem)

					privPemBytes := privPem.Bytes

					var parsedKey interface{}
					if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
						if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
							log.Printf("Unable to parse RSA private key, generating a temp one :%s", err.Error())
						}
					}

					var privateKey *rsa.PrivateKey
					privateKey, ok = parsedKey.(*rsa.PrivateKey)

					rng := rand.Reader

					encKey, _ := hex.DecodeString(mobileObj.EncryptedKey)
					data, err = rsa.DecryptOAEP(sha256.New(), rng, privateKey, encKey, []byte("test"))
				}

				/*		recover_data_object = json.loads(data.decode())
						data = bytearray.fromhex(recover_data_object['key'])
				*/
				var recData RecoveryData

				err = json.Unmarshal(data, &recData)

				if err != nil {
					log.Panic("mobile json parser error ", err)
				}

				data, err = hex.DecodeString(recData.Key)

				if len(data) == 36 {
					// algo = int.from_bytes(data[:4], byteorder='little')

					algo := binary.LittleEndian.Uint64(data[:4])

					data = data[4:]
					//players_data[key_id][get_player_id(key_id, obj["deviceId"], False)] = int.from_bytes(data, byteorder='big')

					playersData[key_id] = map[string]uint64{}
					playersData[key_id][getPlayerId(key_id, cosigner_id, false)] = binary.BigEndian.Uint64(data[4:])

				}
			}
		} else if strings.HasPrefix(name, "metadata.json") {
			continue
		} else {
			if strings.Contains("_", name) {

				names := strings.Split(name, "_")

				cosigner_id = names[0]
				key_id = names[1]

			} else {
				if len(keyMetadataMapping) == 1 {
					cosigner_id = name
					key_id = reflect.ValueOf(keyMetadataMapping).MapKeys()[0].String()
				} else {
					key_id = ""
				}

				if key_id != "" {

					name, _ := ioutil.ReadFile(name)

					fmt.Println("Metadata ", metadata)

					data, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, name, []byte(keyPass))
					playersData[key_id][getPlayerId(key_id, cosigner_id, true)] = binary.BigEndian.Uint64(data)

				}
			}
		}
	}

	for keyId := range keyMetadataMapping {
		if _, ok := playersData[keyId]; !ok {
			//do something here
			fmt.Println("RecoveryErrorKeyIdMissing")
		}
	}

	for keyId, playerData := range playersData {

		algo := keyMetadataMapping[keyId].Algo

		chainCodeForThisKey := keyMetadataMapping[key_id].ChainCodeForThisKey

		privkey, pubkeyStr := CalculateKey(algo, keyId, playerData)

		pubFromMetadata := keyMetadataMapping[keyId].MetadataPublicKey

		if pubFromMetadata != pubkeyStr {
			//print(f"Failed to recover {algo} key, expected public key is: {pub_from_metadata} calculated public key is: {pubkey_str}")
			privateKeys[algo] = PrivateKey{0, nil}
		} else {
			privateKeys[algo] = PrivateKey{privkey, chainCodeForThisKey}
		}
	}

	if len(privateKeys) == 0 {
		fmt.Println("RecoveryErrorPublicKeyNoMatch()")
	}

	return privateKeys
}

//for
/* algo = key_metadata_mapping[key_id][0]
   chain_code_for_this_key = key_metadata_mapping[key_id][2]
   privkey, pubkey_str = calculate_keys(key_id, key_players_data, algo)*/

/*  if is_cloud:
        key_id_first_dword = uuid.UUID(key_id).int.to_bytes(16, 'big')[0:4]
        player_id = int(cosigner_id) << 32 | struct.unpack("I", key_id_first_dword)[0]
    else:
        cosigner_prefix = list(uuid.UUID(cosigner_id).int.to_bytes(16, 'big')[0:6])
        cosigner_prefix.reverse()
        player_id = struct.unpack("Q", bytes(cosigner_prefix) + struct.pack("h", 0))[0]
    return player_id*/

func getPlayerId(keyId string, cosignerId string, isCloud bool) string {
	if isCloud {
		uuid, _ := uuid.Parse(keyId)
		key_id_first_dword := []byte(uuid.String())[0:4]
		//player_id = cosignerId << 32 | struct.unpack("I", key_id_first_dword)[0]
	} else {
		/*cosigner_prefix = list(uuid.UUID(cosigner_id).int.to_bytes(16, 'big')[0:6])
		cosigner_prefix.reverse()
		player_id = struct.unpack("Q", bytes(cosigner_prefix) + struct.pack("h", 0))[0]*/
	}
	return cosignerId
}
