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
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const vaultFile = "vault.db"

const (
	magicBytes    = "CHPD"
	fileVersion   = 1
	keyLength     = 32
	saltLength    = 16
	maxMemoryMB   = 4096
	maxIterations = 100
	maxThreads    = 64
)

type CryptoParams struct {
	Memory     uint32
	Iterations uint32
	Threads    uint8
	Salt       []byte
}

type Vault map[string][]byte

var mu sync.Mutex

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func wipeVault(vault Vault) {
	for _, pwdBytes := range vault {
		wipe(pwdBytes)
	}
}

func readHiddenInput(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	byteInput, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Println()
	return byteInput, nil
}

func readParam(scanner *bufio.Scanner, prompt string, defaultVal uint32, minVal uint32, maxVal uint32) uint32 {
	fmt.Printf("%s [%d]: ", prompt, defaultVal)
	if !scanner.Scan() {
		return defaultVal
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return defaultVal
	}
	val, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		fmt.Printf("Invalid input, using default: %d\n", defaultVal)
		return defaultVal
	}
	
	ret := uint32(val)
	if ret < minVal {
		fmt.Printf("Value below minimum, adjusted to: %d\n", minVal)
		return minVal
	}
	if ret > maxVal {
		fmt.Printf("Value exceeds maximum, adjusted to: %d\n", maxVal)
		return maxVal
	}
	return ret
}

func initCryptoParams(scanner *bufio.Scanner) (CryptoParams, error) {
	fmt.Println("--- Argon2id Hardware Tuning ---")
	fmt.Println("Press ENTER to accept the default value.")
	fmt.Println()
	
	memMB := readParam(scanner, "Allocated memory in MB (Min: 8, Max: 4096, Recommended: 256)", 256, 8, maxMemoryMB)
	iterations := readParam(scanner, "Iterations (Min: 1, Max: 100, Recommended: 4)", 4, 1, maxIterations)
	threads := readParam(scanner, "Parallel threads (Min: 1, Max: 64, Recommended: 4)", 4, 1, maxThreads)

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return CryptoParams{}, err
	}

	return CryptoParams{
		Memory:     memMB * 1024,
		Iterations: iterations,
		Threads:    uint8(threads),
		Salt:       salt,
	}, nil
}

func readCryptoParams() (CryptoParams, error) {
	file, err := os.Open(vaultFile)
	if err != nil {
		return CryptoParams{}, err
	}
	defer file.Close()

	header := make([]byte, 30)
	_, err = io.ReadFull(file, header)
	if err != nil {
		return CryptoParams{}, fmt.Errorf("failed to read database header: %v", err)
	}

	if string(header[:4]) != magicBytes {
		return CryptoParams{}, fmt.Errorf("invalid file format (missing CHPD signature)")
	}

	if header[4] != fileVersion {
		return CryptoParams{}, fmt.Errorf("unsupported file structure version: %d", header[4])
	}

	mem := binary.BigEndian.Uint32(header[5:9])
	iter := binary.BigEndian.Uint32(header[9:13])
	threads := header[13]
	salt := header[14:30]

	if mem > maxMemoryMB*1024 {
		return CryptoParams{}, fmt.Errorf("SECURITY: File requests %d MB RAM. Limit exceeded (max %d MB)", mem/1024, maxMemoryMB)
	}
	if iter > maxIterations {
		return CryptoParams{}, fmt.Errorf("SECURITY: File requests %d iterations. Limit exceeded (max %d)", iter, maxIterations)
	}
	if uint32(threads) > maxThreads {
		return CryptoParams{}, fmt.Errorf("SECURITY: File requests %d threads. Limit exceeded (max %d)", threads, maxThreads)
	}

	return CryptoParams{
		Memory:     mem,
		Iterations: iter,
		Threads:    threads,
		Salt:       salt,
	}, nil
}

func deriveKey(password []byte, params CryptoParams) []byte {
	return argon2.IDKey(password, params.Salt, params.Iterations, params.Memory, params.Threads, keyLength)
}

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

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
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
	return append(nonce, ciphertext...), nil
}

func decrypt(encryptedPayload []byte, key []byte) ([]byte, error) {
	if len(encryptedPayload) < 12 {
		return nil, fmt.Errorf("invalid encrypted payload size")
	}

	nonce := encryptedPayload[:12]
	ciphertext := encryptedPayload[12:]

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

func loadVault(sessionKey []byte, currentParams CryptoParams) (Vault, error) {
	if _, err := os.Stat(vaultFile); os.IsNotExist(err) {
		return make(Vault), nil
	}

	fileData, err := os.ReadFile(vaultFile)
	if err != nil {
		return nil, err
	}

	if len(fileData) < 30+12 {
		return nil, fmt.Errorf("database file is corrupted or truncated")
	}

	encryptedPayload := fileData[30:]
	decryptedData, err := decrypt(encryptedPayload, sessionKey)
	if err != nil {
		return nil, err
	}

	if len(decryptedData) < 9 {
		return nil, fmt.Errorf("decrypted validation payload is truncated")
	}

	origMemory := binary.BigEndian.Uint32(decryptedData[0:4])
	origIterations := binary.BigEndian.Uint32(decryptedData[4:8])
	origThreads := decryptedData[8]

	if origMemory != currentParams.Memory || origIterations != currentParams.Iterations || origThreads != currentParams.Threads {
		return nil, fmt.Errorf("CRITICAL SECURITY ALERT: Database header tampering detected! Original parameters do not match")
	}

	return decodeVault(decryptedData[9:])
}

func saveVault(vault Vault, sessionKey []byte, params CryptoParams) error {
	vaultPlaintext := encodeVault(vault)

	validationBuf := make([]byte, 9)
	binary.BigEndian.PutUint32(validationBuf[0:4], params.Memory)
	binary.BigEndian.PutUint32(validationBuf[4:8], params.Iterations)
	validationBuf[8] = params.Threads

	finalPlaintext := append(validationBuf, vaultPlaintext...)

	encryptedPayload, err := encrypt(finalPlaintext, sessionKey)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	buf.WriteString(magicBytes)
	buf.WriteByte(fileVersion)
	
	memBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(memBuf, params.Memory)
	buf.Write(memBuf)

	iterBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(iterBuf, params.Iterations)
	buf.Write(iterBuf)

	buf.WriteByte(params.Threads)
	buf.Write(params.Salt)
	buf.Write(encryptedPayload)

	tmpFile := vaultFile + ".tmp"
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
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
	var params CryptoParams
	var err error
	var masterPassword []byte
	scanner := bufio.NewScanner(os.Stdin)

	if _, err = os.Stat(vaultFile); os.IsNotExist(err) {
		fmt.Println("========================================================================")
		fmt.Println("⚠️  CRITICAL WARNING: ZERO-KNOWLEDGE CRYPTO VAULT")
		fmt.Println("- CRYPTOGRAPHY: Argon2id key derivation + AES-256-GCM hardware encryption.")
		fmt.Println("- MEMORY SAFETY: Master password is wiped from RAM instantly after boot.")
		fmt.Println("- STORAGE SAFETY: The password is NEVER saved to disk or OS keychains.")
		fmt.Println("- IRREVERSIBLE: If you lose the password, your data is GONE FOREVER.")
		fmt.Println("- PERMANENT: You CANNOT reset, recover, or change the master password.")
		fmt.Println("========================================================================")
		fmt.Println()

		for {
			fmt.Print("Type 'I UNDERSTAND' to confirm and proceed: ")
			if !scanner.Scan() {
				os.Exit(1)
			}
			if strings.TrimSpace(scanner.Text()) == "I UNDERSTAND" {
				break
			}
			fmt.Println("[-] Confirmation failed. You must agree to the terms.")
		}
		fmt.Println()

		params, err = initCryptoParams(scanner)
		if err != nil {
			fmt.Printf("Initialization error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()

		for {
			p1, err := readHiddenInput("Create New Master Password: ")
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			p2, err := readHiddenInput("Confirm New Master Password: ")
			if err != nil {
				wipe(p1)
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			if bytes.Equal(p1, p2) {
				masterPassword = p1
				wipe(p2)
				break
			}
			fmt.Println("[-] Passwords do not match. Try again.")
			wipe(p1)
			wipe(p2)
		}
		fmt.Println("[+] Master Password configured successfully.")
	} else {
		params, err = readCryptoParams()
		if err != nil {
			fmt.Printf("Error reading database configuration: %v\n", err)
			os.Exit(1)
		}

		masterPassword, err = readHiddenInput("Enter Master Password: ")
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}

	sessionKey := deriveKey(masterPassword, params)
	wipe(masterPassword) 
	defer wipe(sessionKey)

	vault, err := loadVault(sessionKey, params)
	if err != nil {
		fmt.Printf("Access Denied: %v\n", err)
		os.Exit(1)
	}
	defer wipeVault(vault)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		mu.Lock() 
		wipe(sessionKey)
		wipeVault(vault)
		fmt.Println("\n[!] Emergency exit. Memory wiped. Vault locked.")
		os.Exit(0)
	}()

	fmt.Println("Vault unlocked. Type 'help' for commands.")

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
			err = saveVault(vault, sessionKey, params)
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
				fmt.Printf("%s: %s\n", service, string(pwdBytes))
				fmt.Print("   [Press ENTER to hide password]")
				scanner.Scan()
				fmt.Print("\r\033[A\033[2K\033[A\033[2K")
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
				err = saveVault(vault, sessionKey, params)
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
				err = saveVault(vault, sessionKey, params)
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
			wipe(sessionKey)
			wipeVault(vault)
			mu.Unlock()
			fmt.Println("Vault locked. Goodbye.")
			return

		default:
			fmt.Println("Unknown command. Type 'help'.")
		}
	}
}
