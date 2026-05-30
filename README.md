WARNING: This is a pure Zero-Knowledge system. There is no back-door, no recovery key, and no "Forgot Password" button. If you lose your master key, your data is gone forever.

## Important Note on First Launch

When you run `chpwd` for the first time, you will go through the Zero-Knowledge disclaimer and the hardware tuning wizard. 

Please note that **the database file (`vault.db`) is physically created only after you add your very first password** using the `add <service>` command. 

If you exit the application immediately after configuring the Master Password without adding any entries, **your settings will not be saved**, and the next launch will trigger the setup wizard and disclaimer again.

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
