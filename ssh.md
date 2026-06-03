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
ssh-keygen -t ed25519 -a 100 -C "$USER@$(hostname)-$(date +%Y-%m-%d)" -f ~/.ssh/id_ed25519
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
