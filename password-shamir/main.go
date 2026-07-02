package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	mathRand "math/rand"
	"sort"
	"time"

	"github.com/etnz/permute"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"golang.org/x/crypto/bcrypt"
)

func xor(key []byte, data []byte) []byte {
	if len(key) < len(data) {
		panic("key is smaller than data")
	}

	result := make([]byte, len(data))
	for i := range len(data) {
		result[i] = key[i] ^ data[i]
	}

	return result
}

func randSelect(hashes [][]byte, num int) [][]byte {
	var results [][]byte

	for len(results) < num {
		selected := mathRand.Intn(len(hashes))
		alreadyChosen := false
		for j := range results {
			if bytes.Equal(hashes[selected], results[j]) {
				alreadyChosen = true
				break
			}
		}

		if !alreadyChosen {
			results = append(results, hashes[selected])
		}
	}

	return results
}

func combine(passwords [][]byte, secured [][]byte, hint []byte) []byte {
	// Sort passwords again.
	sort.SliceStable(passwords, func(i, j int) bool {
		return bytes.Compare(passwords[i], passwords[j]) == -1
	})

	// Try each combination of shares.
	count := 0
	for encodedShares := range permute.Combinations(len(passwords), secured) {
		count += 1
		shares := make([][]byte, len(encodedShares))
		for index := range len(encodedShares) {
			shares[index] = xor(passwords[index], encodedShares[index])
		}

		result, err := shamir.Combine(shares)
		if err != nil {
			continue
		}

		_, err = decrypt(result, hint)
		if err == nil {
			maxCount := 0
			for _ = range permute.Combinations(len(passwords), secured) {
				maxCount += 1
			}

			fmt.Printf("\t\tFound after %v tries of %v\n", count, maxCount)
			return result
		}

		continue
	}

	panic("did not find original ciphertext")
	return nil
}

func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nil, plaintext, nil), nil
}

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nil, ciphertext, nil)
}

func main() {
	maxShares := 33
	maxRequired := 17

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Sprintf("cannot generate key: %v", err))
	}

	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		panic(fmt.Sprintf("cannot generate challenge: %v", err))
	}

	hint, err := encrypt(key, challenge)
	if err != nil {
		panic(fmt.Sprintf("cannot generate hint: %v", err))
	}

	for numShares := range maxShares {
		if numShares <= 1 {
			continue
		}

		var longestTime time.Duration
		var longestRequired int

		for numRequired := range maxRequired {
			if numRequired <= 1 || numRequired > numShares {
				continue
			}
			if numRequired < (numShares/2-2) || numRequired > (numShares/2+2) {
				continue
			}

			fmt.Printf("running: %v of %v\n", numRequired, numShares)

			shares, err := shamir.Split(key, numShares, numRequired)
			if err != nil {
				panic(fmt.Sprintf("cannot create shamir shares for %v of %v: %v", numRequired, numShares, err))
			}

			passwords := make([]string, len(shares))
			for index := range len(shares) {
				passwords[index] = fmt.Sprintf("password-%v", index)
			}

			start := time.Now()
			hashed := make([][]byte, len(shares))
			for index := range len(shares) {
				hash, err := bcrypt.GenerateFromPassword([]byte(passwords[index]), bcrypt.DefaultCost)
				if err != nil {
					panic(fmt.Sprintf("cannot bcrypt: %v", err))
				}

				hashed[index] = hash
			}
			hashRate := time.Now().Sub(start)
			fmt.Printf("\ttime to hash: %v\n", hashRate)

			sort.SliceStable(hashed, func(i, j int) bool {
				return bytes.Compare(hashed[i], hashed[j]) == -1
			})

			securedShares := make([][]byte, len(shares))
			for index := range len(shares) {
				securedShares[index] = xor(hashed[index], shares[index])
			}

			var longestSample time.Duration
			for _ = range 20 {
				chosen := randSelect(hashed, numRequired)
				start := time.Now()
				ret := combine(chosen, securedShares, hint)
				if !bytes.Equal(ret, key) {
					panic("failed to recover key")
				}

				finished := time.Now()
				length := finished.Sub(start)

				if length > longestSample {
					longestSample = length
				}
			}

			if longestSample > longestTime {
				longestTime = longestSample
				longestRequired = numRequired
			}
		}

		fmt.Printf("combining %v of %v took: %v\n\n", longestRequired, numShares, longestTime)
	}
}
