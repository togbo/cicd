import os
import hashlib
import logging
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Utilisation de variables d'environnement pour stocker des secrets
API_KEY = os.getenv('API_KEY')  # Assure-toi que la variable d'environnement est définie
password = os.getenv('password') # Ne jamais stocker des mots de passe en clair dans le code

# Ne jamais exposer directement des secrets dans les logs
logging.basicConfig(filename='app.log', level=logging.INFO)

def secure_logging(user_input):
    # Ne jamais logger des informations sensibles comme un mot de passe
    logging.info("User login attempt: %s", user_input)

def run_code_safe(user_input):
    # Au lieu d'utiliser eval(), traiter les entrées de manière sécurisée
    if user_input not in ['safe_command_1', 'safe_command_2']:  # Liste blanche
        logging.warning(f"Unsafe command attempt: {user_input}")
        return
    # Exécuter une commande sûre
    print(f"Executing command: {user_input}")

def fetch_url_safe():
    url = input("Enter URL to fetch: ")
    if not url.startswith("https://"):  # Validation de l'URL pour éviter les risques
        print("URL must start with 'https://'.")
        return
    try:
        response = requests.get(url)
        print(response.text)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")

def hash_password_safe(pwd):
    # Ne jamais utiliser MD5, utiliser SHA-256 ou bcrypt
    return hashlib.sha256(pwd.encode()).hexdigest()

def encrypt_data_safe(data):
    key = get_random_bytes(16)  # Clé AES de 16 octets (128 bits)
    cipher = AES.new(key, AES.MODE_GCM)  # Utilisation de GCM pour plus de sécurité
    ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode(), AES.block_size))
    return cipher.nonce + tag + ciphertext  # Stocke nonce + tag + ciphertext pour la décryption

def save_file_safe():
    path = input("Enter path to save file: ")
    if not path.endswith(".txt"):  # Validation simple de fichier
        print("Only '.txt' files are allowed.")
        return
    try:
        with open(path, 'w') as f:
            f.write("Untrusted file content")
    except Exception as e:
        logging.error(f"Failed to write file: {e}")

if __name__ == "__main__":
    # Exemple d'utilisation avec des entrées validées
    user_input = input("Username: ")
    secure_logging(user_input)

    # Ne jamais utiliser eval
    run_code_safe(user_input)

    fetch_url_safe()

    # Hash du mot de passe avec SHA-256
    hashed_password = hash_password_safe(password)
    print(f"Hashed password: {hashed_password}")

    # Cryptage des données
    encrypted_data = encrypt_data_safe("Sensitive data")
    print(f"Encrypted data: {encrypted_data}")

    save_file_safe()
