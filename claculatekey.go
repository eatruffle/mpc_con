package restorekey

import (
	"math"
)

const q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

/*
def _prime_mod_inverse(x, p):
    return pow(x, p-2, p)*/

func primeModInverse(x int, p int) int {

	/*
			var i, e, m = big.NewInt(16), big.NewInt(2), big.NewInt(5)
		     i.Exp(i, e, m)
	*/
	t := int(math.Pow(float64(x), float64(p-2)))

	return t % p
}

func lagrangeCoefficient(my_id string, ids []string, field int) uint64 {
	coefficient := 1
	for _, id := range ids {
		if id == my_id {
			tmp := primeModInverse(int(id)-int(my_id)%field, field)
			tmp = (tmp * id) % field
			coefficient *= tmp
		}
	}
	return coefficient
}

/*
def calculate_keys(key_id, player_to_data, algo):
    if algo == "MPC_ECDSA_SECP256K1":
        privkey = 0
        for key, value in player_to_data.items():
            privkey = (privkey + value * lagrange_coefficient(key, player_to_data.keys(), secp256k1.q)) % secp256k1.q

        pubkey = secp256k1.G * privkey
        return privkey, pubkey.serialize()
*/

func CalculateKey(algo string, keyId string, playerToData map[string]uint64) (int, string) {
	privkey := 0
	/*	for key, value in player_to_data.items():
		privkey = (privkey + value * lagrange_coefficient(key, player_to_data.keys(), secp256k1.q)) % secp256k1.q
	*/

	keys := make([]string, len(playerToData))

	i := 0
	for k := range playerToData {
		keys[i] = k
		i++
	}

	for key, value := range playerToData {
		privkey = int((uint64(privkey) + value*lagrangeCoefficient(key, keys, q)) % q)
	}

	pubKey := Point{
		0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
		0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
	}.mul(privkey)

	return privkey, pubKey.serialize(true)
}
