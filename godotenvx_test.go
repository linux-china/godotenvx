package godotenvx

import (
	"log"
	"os"
	"testing"

	ecies "github.com/ecies/go/v2"
	"github.com/joho/godotenv"
)

func TestLoadDotenv(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	s3Bucket := os.Getenv("S3_BUCKET")
	secretKey := os.Getenv("SECRET_KEY")
	log.Println(s3Bucket, secretKey)
}

func TestLoadDotenvx(t *testing.T) {
	err := Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	s3Bucket := os.Getenv("S3_BUCKET")
	secretKey := os.Getenv("SECRET_KEY")
	log.Println(s3Bucket, secretKey)
}

func TestDecryptItem(t *testing.T) {
	privateKeyHex := FindPrivateKey("")
	encryptedText := "encrypted:BB01667tzu9aa7LFz8cUOQrDf/sU/PygTvTRD6DG5oNGlgfoXNEA5LvLuPPgcK2JCwiuweAenZNxJdBem7XuQFn1R7l9X0OtDl7SfPdXctfdZZI2QKxaCfWokalnNbCvhb+kXZxESHCnXU3FMQ=="
	textPlain, err := DecryptDotenvxItem(privateKeyHex, encryptedText)
	if err != nil {
		panic(err)
	}
	log.Println(textPlain)
}

func TestEcies(t *testing.T) {
	k, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	log.Println("key pair has been generated")

	ciphertext, err := ecies.Encrypt(k.PublicKey, []byte("THIS IS THE TEST"))
	if err != nil {
		panic(err)
	}
	log.Printf("plaintext encrypted: %v\n", ciphertext)
	plaintext, err := ecies.Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	log.Printf("ciphertext decrypted: %s\n", string(plaintext))
}
