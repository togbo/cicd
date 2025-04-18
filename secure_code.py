import os
import hashlib
import logging
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv

# Charger les secrets à partir d'un fichier .env (ne jamais mettre .env dans le contrôle de version)
load_dotenv()

# Utilisation de variables d'environnement pour les clés API et les mots de passe
API_KEY = os.getenv('API_KEY')  # Clé API sécurisée dans les variables d'environnement
password = os.getenv('PASSWORD')  # Mot de passe sécurisé dans les variables d'environnement

if API_KEY is None:
    raise ValueError("API_KEY is not set in the environment variables")
if password is None:
    raise ValueError("PASSWORD is not set in the environment variables")

# Sécuriser la gestion des logs (ne jamais enregistrer des informations sensibles)
logging.basicConfig(filename='app.log', level=logging.INFO)

def secure_logging(user_input):
    # Ne jamais logger des informations sensibles comme un mot de passe ou une clé API
    logging.info("User login attempt: %s", user_input)

def run_code_safe(user_input):
    # Ne jamais utiliser eval(), traiter les entrées de manière sécurisée
    safe_commands = ['safe_command_1', 'safe_command_2']
    
    if user_input not in safe_commands:  # Liste blanche
        logging.warning(f"Unsafe command attempt: {user_input}")
        return
    # Exécution d'une commande sûre
    print(f"Executing command: {user_input}")

def fetch_url_safe():
    url = input("Enter URL to fetch: ")
    if not url.startswith("https://"):  # Validation de l'URL
        print("URL must start with 'https://'.")
        return
    try:
        response = requests.get(url)
        response.raise_for_status()  # Vérifier si la requête a réussi
        print(response.text)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")

def hash_password_safe(pwd):
    # Utilisation de SHA-256 au lieu de MD5 (plus sécurisé)
    return hashlib.sha256(pwd.encode()).hexdigest()

def encrypt_data_safe(data):
    key = get_random_bytes(16)  # Générer une clé AES de 16 octets
    cipher = AES.new(key, AES.MODE_GCM)  # Utilisation du mode GCM pour plus de sécurité
    ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode(), AES.block_size))
    
    # Retourner le nonce + tag + ciphertext pour la décryption sécurisée
    return cipher.nonce + tag + ciphertext

def decrypt_data_safe(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
    return decrypted_data.decode()

def save_file_safe():
    path = input("Enter path to save file: ")
    if not path.endswith(".txt"):  # Validation de l'extension de fichier
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

    # Exécuter une commande en toute sécurité (sans eval)
    run_code_safe(user_input)

    # Faire une requête sécurisée (avec validation de l'URL)
    fetch_url_safe()

    # Hachage du mot de passe avec SHA-256
    hashed_password = hash_password_safe(password)
    print(f"Hashed password: {hashed_password}")

    # Cryptage et décryptage des données en toute sécurité
    encrypted_data = encrypt_data_safe("Sensitive data")
    print(f"Encrypted data: {encrypted_data}")

    # Décryptage des données
    decrypted_data = decrypt_data_safe(encrypted_data, get_random_bytes(16))
    print(f"Decrypted data: {decrypted_data}")

    # Sauvegarde sécurisée du fichier
    save_file_safe()
