package sw

import (
	"crypto/pqc/dilithium/dilithium5"
	"fmt"
)

func main() {
	fmt.Println("Testing Dilithium5 import...")

	key, err := dilithium5.GenerateKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Dilithium5 key generated successfully: %d bytes\n", len(key.PublicKey))
}
