package hash_utils

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type CryptoUtils struct{}

func (c *CryptoUtils) H1(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (c *CryptoUtils) H2(args ...[]byte) *big.Int {
	var data []byte
	for _, arg := range args {
		data = append(data, arg...)
	}

	hash := sha256.Sum256(data)
	hashInt := new(big.Int).SetBytes(hash[:])

	curve := elliptic.P256()
	n := curve.Params().N

	qMinus1 := new(big.Int).Sub(n, big.NewInt(1))
	result := new(big.Int).Mod(hashInt, qMinus1)
	result.Add(result, big.NewInt(1))

	return result
}

func (c *CryptoUtils) H3(x, y *big.Int) []byte {
	compressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)

	hash := sha3.Sum512(compressed)
	return hash[:43]
}

func (c *CryptoUtils) H3_1(x, y *big.Int) []byte {
	compressed := elliptic.MarshalCompressed(elliptic.P256(), x, y)

	hash := sha3.Sum512(compressed)
	return hash[:37]
}

func (c *CryptoUtils) H4(data []byte) []byte {
	shake := sha3.NewShake128()
	shake.Write(data)

	result := make([]byte, 32)
	shake.Read(result)

	return result
}

func BigIntToBytes32(n *big.Int) []byte {
	bytes := n.Bytes()

	if len(bytes) > 32 {
		return bytes[len(bytes)-32:]
	}

	result := make([]byte, 32)
	copy(result[32-len(bytes):], bytes)

	return result
}

func Uint64ToBytes(n uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, n)

	return bytes
}