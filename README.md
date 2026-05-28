WARNING: This is a pure Zero-Knowledge system. There is no back-door, no recovery key, and no "Forgot Password" button. If you lose your master key, your data is gone forever. Don't text me asking for ways to recover your passwords. You can cry about it.

# chpwd

A minimal and highly secure CLI password manager for Linux. 

## Features
* **Strong Crypto:** Uses AES-256-GCM for encryption and Argon2id for master password key derivation.
* **Memory Security:** Explicitly wipes master keys and sensitive data from RAM immediately after use.
* **Interactive UI:** REPL shell environment with hidden password input to prevent terminal history leaks.

## Installation

### Arch Linux (AUR)
```bash
yay -S chpwd
```

### From Source (Requires Go)
```bash
git clone https://github.com/b0lbas/chpwd.git
cd chpwd
go build -o chpwd main.go
sudo mv chpwd /usr/local/bin/
```

## Usage
Simply launch the utility from any terminal:
```bash
chpwd
```
Enter your master password to unlock the database. Once inside the internal shell, use the following commands:

* `help` — Show available commands.
* `add <service> <password>` — Save a new password.
* `get <service>` — Retrieve a password.
* `mod <service> <password>` — Update an existing password.
* `del <service>` — Delete a password from the vault.
* `exit` — Securely lock the vault and quit.

## License
MIT
