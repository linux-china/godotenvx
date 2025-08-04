package godotenvx

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	ecies "github.com/ecies/go/v2"
	dotenv "github.com/joho/godotenv"
)

// Load will read your .env file and load them into ENV for this process.
//
// You can otherwise tell it which files to load (there can be more than one) like:
//
//	godotenvx.Load()
//
// It's important to note that it WILL OVERRIDE an env variable that already exists.
func Load() (err error) {
	return LoadFile(".env")
}

// LoadFile Load will read your env file(s) and load them into ENV for this process.
//
// Call this function as close as possible to the start of your program (ideally in main).
//
// If you call Load without any args it will default to loading .env in the current path.
//
// You can otherwise tell it which files to load (there can be more than one) like:
//
//	godotenvx.Load(".env")
//
// It's important to note that it WILL OVERRIDE an env variable that already exists.
func LoadFile(filename string) (err error) {
	profile := getProfile(filename)
	envMap, err := dotenv.Read(filename)
	if err != nil {
		return err
	}
	return decryptAndLoad(profile, envMap)
}

func LoadReader(profile string, r io.Reader) (err error) {
	envMap, err := dotenv.Parse(r)
	if err != nil {
		return err
	}
	return decryptAndLoad(profile, envMap)
}

// decryptAndLoad decrypts the encrypted items in the envMap and inserts them into the environment variables.
func decryptAndLoad(profile string, envMap map[string]string) (err error) {
	hasEncryptedItem := false
	for _, value := range envMap {
		if strings.HasPrefix(value, "encrypted:") {
			hasEncryptedItem = true
			break
		}
	}
	if hasEncryptedItem {
		privateKeyHex := FindPrivateKey(profile)
		if privateKeyHex == "" {
			return fmt.Errorf("private key not found")
		}
		for key, value := range envMap {
			if strings.HasPrefix(value, "encrypted:") {
				envMap[key], err = DecryptDotenvxItem(privateKeyHex, value)
				if err != nil {
					return err
				}
			}
		}
	}
	// set envMap to os.Environ()
	for key, value := range envMap {
		_ = os.Setenv(key, value)
	}
	return
}

func getProfile(filename string) string {
	// read profile from env
	envProfileNames := [5]string{"APP_ENV", "NODE_ENV"}
	for _, envProfileName := range envProfileNames {
		if envProfileValue := os.Getenv(envProfileName); envProfileValue != "" {
			return envProfileValue
		}
	}
	if strings.HasPrefix(filename, ".env.") {
		return strings.TrimPrefix(filename, ".env.")
	}
	return ""
}

func FindPrivateKey(profile string) string {
	privateKeyName := "DOTENV_PRIVATE_KEY"
	if profile != "" {
		privateKeyName = privateKeyName + "_" + strings.ToUpper(profile)
	}
	dotenvKeysFile := findDotenvKeysFile()
	privateKeyHex := ""
	if dotenvKeysFile != "" {
		keysMap, _ := dotenv.Read(dotenvKeysFile)
		keyValue, exists := keysMap[privateKeyName]
		if exists {
			privateKeyHex = keyValue
		}
	}
	if privateKeyHex == "" {
		privateKeyHex = os.Getenv(privateKeyName)
	}
	return privateKeyHex
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// find .env.keys file in current directory and parent directories
func findDotenvKeysFile() string {
	current, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		keysFile := current + string(os.PathSeparator) + ".env.keys"
		if fileExists(keysFile) {
			return keysFile
		}
		parent := current[:strings.LastIndex(current, string(os.PathSeparator))]
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

func DecryptDotenvxItem(privateKeyHex string, encryptedText string) (string, error) {
	privateKey, err := ecies.NewPrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(encryptedText, "encrypted:") {
		encryptedText = encryptedText[10:]
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}
	plaintext, err := ecies.Decrypt(privateKey, decodedBytes)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
