# Create and Secure an SSH Key on Debian 13 Desktop

## 1. Install the SSH client

```bash
sudo apt update
sudo apt install openssh-client
```

## 2. Create the `.ssh` directory with secure permissions

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
```

## 3. Generate a new Ed25519 SSH key

```bash
ssh-keygen -t ed25519 -a 200 -C "$USER@$(hostname)-$(date +%Y-%m-%d)" -f ~/.ssh/id_ed25519
```

When prompted, enter a strong passphrase.

This creates:

```text
~/.ssh/id_ed25519      # private key — never share this
~/.ssh/id_ed25519.pub  # public key — safe to copy to servers
```

## 4. Fix key permissions

```bash
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
```

## 5. Start the SSH agent and add the key

```bash
eval "$(ssh-agent -s)"
ssh-add -t 8h ~/.ssh/id_ed25519
```

## 6. Check that the key is loaded

```bash
ssh-add -l
```

## 7. Copy the public key to a server

Replace `user` and `server-ip-or-hostname` with your actual SSH username and server address.

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server-ip-or-hostname
```

## 8. Test the connection

```bash
ssh user@server-ip-or-hostname
```

## 9. Optional: create an SSH config entry

```bash
nano ~/.ssh/config
```

Example config:

```sshconfig
Host myserver
    HostName 192.168.1.50
    User darko
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    AddKeysToAgent yes
```

Secure the config file:

```bash
chmod 600 ~/.ssh/config
```

Connect using the shortcut:

```bash
ssh myserver
```

## 10. Change the key passphrase later if needed

```bash
ssh-keygen -p -f ~/.ssh/id_ed25519
```

## Important security note

Never share or upload this file:

```text
~/.ssh/id_ed25519
```

The public key is safe to share:

```text
~/.ssh/id_ed25519.pub
```

# Copy Files Over SSH Using a Private Key

These examples show how to copy files from a local Debian/Linux device to a Debian server that only accepts SSH key authentication.

## 1. Basic `scp` command

```bash
scp -i ~/.ssh/id_ed25519 /path/to/local/file username@server_ip:/path/on/server/
```

### Example

```bash
scp -i ~/.ssh/id_ed25519 ~/Documents/report.txt debian@203.0.113.10:/home/debian/
```

---

## 2. Copy file to a specific directory on the server

```bash
scp -i ~/.ssh/id_ed25519 ~/file.txt debian@203.0.113.10:/home/debian/uploads/
```

---

## 3. Copy file using a custom SSH port

Use `-P` with uppercase `P`.

```bash
scp -i ~/.ssh/id_ed25519 -P 2222 ~/file.txt debian@203.0.113.10:/home/debian/
```

---

## 4. Copy a whole directory

Use `-r` for recursive copy.

```bash
scp -i ~/.ssh/id_ed25519 -r ~/myfolder debian@203.0.113.10:/home/debian/
```

---

## 5. Set correct permissions for your SSH private key

SSH may reject the key if permissions are too open.

```bash
chmod 600 ~/.ssh/id_ed25519
```

---

## 6. Test SSH connection first

```bash
ssh -i ~/.ssh/id_ed25519 debian@203.0.113.10
```

With custom port:

```bash
ssh -i ~/.ssh/id_ed25519 -p 2222 debian@203.0.113.10
```

---

## 7. Alternative: use `rsync`

`rsync` is better for large files or repeated transfers.

```bash
rsync -avz -e "ssh -i ~/.ssh/id_ed25519" ~/Documents/report.txt debian@203.0.113.10:/home/debian/
```

With custom SSH port:

```bash
rsync -avz -e "ssh -i ~/.ssh/id_ed25519 -p 2222" ~/Documents/report.txt debian@203.0.113.10:/home/debian/
```

---

## Replace these values

| Placeholder | Meaning |
|---|---|
| `~/.ssh/id_ed25519` | Path to your private SSH key |
| `~/Documents/report.txt` | File on your local device |
| `debian` | Username on the server |
| `203.0.113.10` | Server IP address |
| `/home/debian/` | Destination path on the server |
| `2222` | Custom SSH port, if used |
