package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
)

type ConfFile struct {
	KeyFile   string `json:"keyfile"`
	ProofFile string `json:"prooffile"`
}

type ProofFile struct {
	Election string      `json:"election"`
	Proofs   []JsonProof `json:"proofs"`
}

type JsonProof struct {
	Ciphertext string `json:"ciphertext"`
	Message    string `json:"message"`
	Proof      string `json:"proof"`
}

type PublicKey struct {
	A asn1.RawValue // We don't actually need this value
	K asn1.BitString
}

type Key struct {
	Key *big.Int
}

type Ciphertext struct {
	A asn1.RawValue // We don't actually need this value
	S struct {
		U *big.Int
		V *big.Int
	}
}

type DecryptionProof struct {
	A *big.Int
	B *big.Int
	S *big.Int
}

type NIProof struct {
	NIPROOFDOMAIN asn1.RawValue
	Pubkey        asn1.RawValue
	Ciphertext    asn1.RawValue
	Decrypted     []byte
	MsgCommitment *big.Int
	KeyCommitment *big.Int
}

// Compute the NIZK challenge from the given seed

func challenge(seed []byte, bound *big.Int) []byte {
	var counter uint64 = 1
	var val []byte
	for true {
		val = []byte{}
		for i := 1; i <= 12; i++ {
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, counter)
			h := sha256.Sum256(append(b, seed...))
			val = append(val, h[:]...)
			counter++
		}
		// We know that q is 3071 bits long, so we mask away the highest bit of the candidate value
		if val[0] >= 128 {
			val[0] -= 128
		}
		y := new(big.Int)
		y.SetBytes(val)
		if y.Cmp(bound) == -1 {
			break
		}
	}
	return val
}

func main() {

	// Load the configuration

	content, err := os.ReadFile("./config.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var conf ConfFile

	err = json.Unmarshal(content, &conf)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pemfilename := conf.KeyFile
	prooffilename := conf.ProofFile

	fmt.Println("Successfully loaded the configuration.")

	// Extract the public key from the file

	pemfile, err := os.Open(pemfilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer pemfile.Close()

	scanner := bufio.NewScanner(pemfile)
	var asn1string string = ""
	for scanner.Scan() {
		s := scanner.Text()
		if s[0:5] != "-----" {
			asn1string += s
		}
	}

	SubjectPublicKeyInfo, err := base64.StdEncoding.DecodeString(asn1string)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

	var pk PublicKey
	_, err = asn1.Unmarshal(SubjectPublicKeyInfo, &pk)
	if err != nil {
		panic(err)
	}

	var kval Key
	_, err = asn1.Unmarshal(pk.K.Bytes, &kval)
	if err != nil {
		panic(err)
	}

	fmt.Println("Successfully loaded the public key.")

	// The base prime comes from the standard, so we do not need to parse it
	pString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

	p := new(big.Int)
	p.SetString(pString, 16)

	// p = 2*q + 1, hence q = (p-1) / 2
	q := new(big.Int)
	q.Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))

	// g = 2 also comes from the standard
	g := big.NewInt(2)

	// Needed for comparison later

	one := big.NewInt(1)

	// Read proofs from the JSON file

	proofFile, err := os.ReadFile(prooffilename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var proofdata ProofFile

	err = json.Unmarshal(proofFile, &proofdata)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proofs := proofdata.Proofs

	fmt.Printf("Successfully loaded %d proof records.\n", len(proofs))

	// Counters for verification successes and failures

	passCount := 0
	failCount := 0

	// We will make use of Go's multithreading

	var wg sync.WaitGroup
	wg.Add(len(proofs))

	var mu sync.Mutex

	// We will also count the results

	var results map[string]int
	results = make(map[string]int)

	// Check the proofs

	for i := 0; i < len(proofs); i++ {

		// Set up multi-threading

		go func(i int) {
			defer wg.Done()

			// To get some visible feedback on the process,
			// we display the counter at every 10000 proofs processed

			if i%10000 == 9999 {
				fmt.Printf("Proof number %d\n", i+1)
			}

			// Extract u and v values from the ciphertext

			EncryptedBallotBase64 := proofs[i].Ciphertext

			EncryptedBallot, err := base64.StdEncoding.DecodeString(EncryptedBallotBase64)
			if err != nil {
				fmt.Print(err)
				os.Exit(1)
			}

			var c Ciphertext
			_, err = asn1.Unmarshal(EncryptedBallot, &c)
			if err != nil {
				fmt.Print(err)
				os.Exit(1)
			}

			// Convert the message to a group element

			message := []byte(proofs[i].Message)
			l := len(message)
			mslice := append([]byte{0, 1}, bytes.Repeat([]byte{255}, 384-l-3)...)
			mslice = append(mslice, []byte{0}...)
			mslice = append(mslice, message...)
			m := new(big.Int)
			m.SetBytes(mslice)

			// Check if m is a quadratic residue, and if not, replace it by -m mod (p)

			// We know from Euler that m is a quadratic residue iff m^q = 1 mod (p)

			e := new(big.Int).Exp(m, q, p)
			if e.Cmp(one) != 0 {
				m.Sub(p, m)
			}

			// Extract a, b and s values from the proof

			DecryptionProofBase64, err := base64.StdEncoding.DecodeString(proofs[i].Proof)
			if err != nil {
				fmt.Print(err)
				os.Exit(1)
			}

			var dp DecryptionProof
			_, err = asn1.Unmarshal(DecryptionProofBase64, &dp)
			if err != nil {
				fmt.Print(err)
				os.Exit(1)
			}

			// Construct the proof challenge seed

			niproof := NIProof{
				NIPROOFDOMAIN: asn1.RawValue{Tag: asn1.TagGeneralString, Bytes: []byte("DECRYPTION")},
				Pubkey:        asn1.RawValue{FullBytes: SubjectPublicKeyInfo},
				Ciphertext:    asn1.RawValue{FullBytes: EncryptedBallot},
				Decrypted:     []byte(proofs[i].Message),
				MsgCommitment: dp.A,
				KeyCommitment: dp.B}

			seed, err := asn1.Marshal(niproof)
			if err != nil {
				panic(err)
			}

			// Compute the challenge value k from the seed

			k := new(big.Int)
			out := challenge(seed, q)
			k.SetBytes(out)

			// Compute u^s

			us := new(big.Int).Exp(c.S.U, dp.S, p)

			// Compute r = a ∗ (v/m)^k mod(p)

			r := new(big.Int).ModInverse(m, p)
			r.Mul(r, c.S.V)
			r.Mod(r, p)
			r.Exp(r, k, p)
			r.Mul(dp.A, r)
			r.Mod(r, p)

			// Compute g^s

			gs := new(big.Int).Exp(g, dp.S, p)

			// Compute t = b ∗ h^k mod(p)

			t := new(big.Int).Exp(kval.Key, k, p)
			t.Mul(dp.B, t)
			t.Mod(t, p)

			// Verify that u^s = a ∗ (v/m)^k mod(p) and g^s = b ∗ h^k mod(p)

			mu.Lock() // We need to lock the counters due to multi-threading
			if (us.Cmp(r) == 0) && (gs.Cmp(t) == 0) {
				passCount += 1
				results[string(message)] += 1
			} else {
				failCount += 1
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	fmt.Printf("Successfully verified: %d.\n", passCount)
	fmt.Printf("Failed verifications: %d.\n\n", failCount)

	// Iterate over the keys of the result map to print out the vote counts.
	for key, val := range results {
		fmt.Printf("Candidate %s got %d votes.\n", key, val)
	}
}
