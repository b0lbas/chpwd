package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const vaultFile = "vault.db"

const (
	argonMemory     = 64 * 1024
	argonIterations = 3
	argonThreads    = 2
	keyLength       = 32
	saltLength      = 16
)

type Vault map[string]string

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func readMasterPassword() []byte {
	fmt.Print("Enter Master Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("\nError reading password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()
	return bytePassword
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonIterations, argonMemory, argonThreads, keyLength)
}

func encrypt(plaintext []byte, password []byte) ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	encryptedData := append(salt, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return encryptedData, nil
}

func decrypt(encryptedData []byte, password []byte) ([]byte, error) {
	if len(encryptedData) < saltLength+12 {
		return nil, fmt.Errorf("invalid or corrupted database")
	}

	salt := encryptedData[:saltLength]
	nonce := encryptedData[saltLength : saltLength+12]
	ciphertext := encryptedData[saltLength+12:]

	key := deriveKey(password, salt)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong master password or corrupted data")
	}

	return plaintext, nil
}

func loadVault(password []byte) Vault {
	vault := make(Vault)
	if _, err := os.Stat(vaultFile); os.IsNotExist(err) {
		return vault
	}

	encryptedData, err := os.ReadFile(vaultFile)
	if err != nil {
		fmt.Printf("File error: %v\n", err)
		os.Exit(1)
	}

	decryptedData, err := decrypt(encryptedData, password)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		os.Exit(1)
	}

	if err := json.Unmarshal(decryptedData, &vault); err != nil {
		fmt.Printf("Parsing error: %v\n", err)
		os.Exit(1)
	}

	return vault
}

func saveVault(vault Vault, password []byte) {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		fmt.Printf("JSON error: %v\n", err)
		os.Exit(1)
	}

	encryptedData, err := encrypt(plaintext, password)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(vaultFile, encryptedData, 0600); err != nil {
		fmt.Printf("Write error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Commands:")
	fmt.Println("  add <service> <password>  - Create a new password")
	fmt.Println("  get <service>             - Read a password")
	fmt.Println("  mod <service> <password>  - Modify an existing password")
	fmt.Println("  del <service>             - Delete a password")
	fmt.Println("  help                      - Show this menu")
	fmt.Println("  exit                      - Close the application")
}

func main() {
	masterPassword := readMasterPassword()
	vault := loadVault(masterPassword)

	fmt.Println("Vault unlocked. Type 'help' for commands.")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("chpwd> ")
		if !scanner.Scan() {
			break
		}

		line := scanner.Text()
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}

		switch args[0] {
		case "help":
			printHelp()

		case "add":
			if len(args) < 3 {
				fmt.Println("Usage: add <service> <password>")
				continue
			}
			service := args[1]
			if _, exists := vault[service]; exists {
				fmt.Println("Error: Service already exists. Use 'mod' to change it.")
				continue
			}
			vault[service] = args[2]
			saveVault(vault, masterPassword)
			fmt.Println("Success: Password saved.")

		case "get":
			if len(args) < 2 {
				fmt.Println("Usage: get <service>")
				continue
			}
			service := args[1]
			if pwd, exists := vault[service]; exists {
				fmt.Printf("%s: %s\n", service, pwd)
			} else {
				fmt.Println("Error: Service not found.")
			}

		case "mod":
			if len(args) < 3 {
				fmt.Println("Usage: mod <service> <password>")
				continue
			}
			service := args[1]
			if _, exists := vault[service]; exists {
				vault[service] = args[2]
				saveVault(vault, masterPassword)
				fmt.Println("Success: Password updated.")
			} else {
				fmt.Println("Error: Service not found.")
			}

		case "del":
			if len(args) < 2 {
				fmt.Println("Usage: del <service>")
				continue
			}
			service := args[1]
			if _, exists := vault[service]; exists {
				delete(vault, service)
				saveVault(vault, masterPassword)
				fmt.Println("Success: Password deleted.")
			} else {
				fmt.Println("Error: Service not found.")
			}

		case "exit":
			wipe(masterPassword)
			fmt.Println("Vault locked. Goodbye.")
			return

		default:
			fmt.Println("Unknown command. Type 'help'.")
		}
	}
}
