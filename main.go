package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
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

type Vault map[string][]byte

var mu sync.Mutex

// wipe — гарантированно очищает память, игнорируя попытки компилятора оптимизировать цикл
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b) // Запрещаем компилятору вырезать этот цикл (Dead Store Elimination)
}

func wipeVault(vault Vault) {
	for _, pwdBytes := range vault {
		wipe(pwdBytes)
	}
}

// readHiddenInput — универсальный скрытый ввод, работающий на всех ОС через os.Stdin.Fd()
func readHiddenInput(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	byteInput, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Println()
	return byteInput, nil
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonIterations, argonMemory, argonThreads, keyLength)
}

// Бинарный формат кодирования (ноль строк в куче)
func encodeVault(v Vault) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(v)))
	for k, val := range v {
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(k)))
		buf.WriteString(k)
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(val)))
		buf.Write(val)
	}
	return buf.Bytes()
}

func decodeVault(data []byte) (Vault, error) {
	vault := make(Vault)
	if len(data) == 0 {
		return vault, nil
	}
	buf := bytes.NewReader(data)
	
	var count uint32
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	
	for i := uint32(0); i < count; i++ {
		var kLen uint32
		if err := binary.Read(buf, binary.BigEndian, &kLen); err != nil {
			return nil, err
		}
		kBytes := make([]byte, kLen)
		if _, err := buf.Read(kBytes); err != nil {
			return nil, err
		}
		
		var vLen uint32
		if err := binary.Read(buf, binary.BigEndian, &vLen); err != nil {
			return nil, err
		}
		vBytes := make([]byte, vLen)
		if _, err := buf.Read(vBytes); err != nil {
			return nil, err
		}
		
		vault[string(kBytes)] = vBytes
	}
	return vault, nil
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
		return nil, fmt.Errorf("invalid database file")
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

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func loadVault(password []byte) (Vault, error) {
	if _, err := os.Stat(vaultFile); os.IsNotExist(err) {
		return make(Vault), nil
	}

	encryptedData, err := os.ReadFile(vaultFile)
	if err != nil {
		return nil, err
	}

	decryptedData, err := decrypt(encryptedData, password)
	if err != nil {
		return nil, err
	}

	return decodeVault(decryptedData)
}

func saveVault(vault Vault, password []byte) error {
	plaintext := encodeVault(vault)
	encryptedData, err := encrypt(plaintext, password)
	if err != nil {
		return err
	}

	tmpFile := vaultFile + ".tmp"
	if err := os.WriteFile(tmpFile, encryptedData, 0600); err != nil {
		return err
	}

	if _, err := os.Stat(vaultFile); err == nil {
		_ = os.Remove(vaultFile)
	}

	return os.Rename(tmpFile, vaultFile)
}

func printHelp() {
	fmt.Println("Commands:")
	fmt.Println("  add <service>  - Create a new password")
	fmt.Println("  get <service>  - Read a password")
	fmt.Println("  mod <service>  - Modify an existing password")
	fmt.Println("  del <service>  - Delete a password")
	fmt.Println("  help           - Show this menu")
	fmt.Println("  exit           - Close the application")
}

func main() {
	masterPassword, err := readHiddenInput("Enter Master Password: ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer wipe(masterPassword) 

	vault, err := loadVault(masterPassword)
	if err != nil {
		wipe(masterPassword)
		fmt.Printf("Access Denied: %v\n", err)
		os.Exit(1)
	}
	defer wipeVault(vault)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		mu.Lock() 
		wipe(masterPassword)
		wipeVault(vault)
		fmt.Println("\n[!] Emergency exit. Memory wiped. Vault locked.")
		os.Exit(0)
	}()

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
			if len(args) < 2 {
				fmt.Println("Usage: add <service>")
				continue
			}
			service := args[1] 
			
			mu.Lock()
			_, exists := vault[service]
			mu.Unlock()
			
			if exists {
				fmt.Println("Error: Service already exists.")
				continue
			}
			
			passwordBytes, err := readHiddenInput("Enter password for " + service + ": ")
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			
			mu.Lock()
			vault[service] = passwordBytes
			err = saveVault(vault, masterPassword)
			mu.Unlock()

			if err != nil {
				fmt.Printf("Save error: %v\n", err)
			} else {
				fmt.Println("Success: Password saved.")
			}

		case "get":
			if len(args) < 2 {
				fmt.Println("Usage: get <service>")
				continue
			}
			service := args[1]
			
			mu.Lock()
			pwdBytes, exists := vault[service]
			if exists {
				fmt.Printf("%s: %s\n", service, pwdBytes)
			} else {
				fmt.Println("Error: Service not found.")
			}
			mu.Unlock()

		case "mod":
			if len(args) < 2 {
				fmt.Println("Usage: mod <service>")
				continue
			}
			service := args[1]
			
			mu.Lock()
			_, exists := vault[service]
			mu.Unlock()

			if exists {
				passwordBytes, err := readHiddenInput("Enter new password for " + service + ": ")
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}
				
				mu.Lock()
				vault[service] = passwordBytes
				err = saveVault(vault, masterPassword)
				mu.Unlock()

				if err != nil {
					fmt.Printf("Save error: %v\n", err)
				} else {
					fmt.Println("Success: Password updated.")
				}
			} else {
				fmt.Println("Error: Service not found.")
			}

		case "del":
			if len(args) < 2 {
				fmt.Println("Usage: del <service>")
				continue
			}
			service := args[1]
			
			mu.Lock()
			pwdBytes, exists := vault[service]
			if exists {
				wipe(pwdBytes)
				delete(vault, service)
				err = saveVault(vault, masterPassword)
			} else {
				fmt.Println("Error: Service not found.")
			}
			mu.Unlock()

			if exists && err != nil {
				fmt.Printf("Save error: %v\n", err)
			} else if exists {
				fmt.Println("Success: Password deleted.")
			}

		case "exit":
			mu.Lock() 
			wipe(masterPassword)
			wipeVault(vault)
			mu.Unlock()
			fmt.Println("Vault locked. Goodbye.")
			return

		default:
			fmt.Println("Unknown command. Type 'help'.")
		}
	}
}
