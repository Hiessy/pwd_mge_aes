import password_vault

# Create a key from a password
key = password_vault.create_key("my_secure_password")

# Create a vault manager
vault = password_vault.PyVaultManager(key, "my_vault.dat")

# Create some entries
entry1 = password_vault.PyPasswordEntry(
    "example.com",
    "user1",
    "password123",
    "Work account",
    ["work", "important"]
)

entry2 = password_vault.PyPasswordEntry(
    "social.com",
    "user2",
    "pass456",
    "Personal account",
    ["social"]
)

# Save entries to vault
vault.save([entry1, entry2])

# Load entries from vault
loaded_entries = vault.load()
for entry in loaded_entries:
    print(entry.to_dict())