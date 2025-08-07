# CRYPTOGRAPHY SCRIPTS TRIAL AES

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import os

# AES - CLAVE DE 256 bits
key = os.urandom(32)
iv = os.urandom(16)

def aes_encrypt(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# PRUEBA 1 - AES
pacientes = [
    {"nombre": "Andrés Torres", "edad": 60, "grupo_sanguineo": "O-", "diagnostico": "Diabetes tipo 2", "sintomas": "Pérdida de peso, visión borrosa", "tratamiento": "Insulina, Glibenclamida", "recomendaciones": "Monitoreo glucémico intensivo, cambio en hábitos alimenticios"},
    {"nombre": "Carlos Méndez", "edad": 58, "grupo_sanguineo": "O+", "diagnostico": "Diabetes tipo 2", "sintomas": "Fatiga, sed excesiva, visión borrosa", "tratamiento": "Metformina, Insulina", "recomendaciones": "Control glicémico, dieta baja en carbohidratos, ejercicio regular"},
    {"nombre": "Diego Londoño", "edad": 29, "grupo_sanguineo": "A+", "diagnostico": "Miastenia gravis", "sintomas": "Debilidad muscular, visión doble", "tratamiento": "Piridostigmina, Corticoides", "recomendaciones": "Terapia inmunosupresora, ejercicios de respiración"},
    {"nombre": "Elena Vargas", "edad": 43, "grupo_sanguineo": "B+", "diagnostico": "Asma", "sintomas": "Sibilancias, dificultad para respirar", "tratamiento": "Formoterol, Fluticasona", "recomendaciones": "Terapia broncodilatadora, evitar factores desencadenantes"},
    {"nombre": "Isabela Fonseca", "edad": 41, "grupo_sanguineo": "B+", "diagnostico": "Síndrome de Cushing", "sintomas": "Obesidad central, cara redonda", "tratamiento": "Ketoconazol, Mifepristona", "recomendaciones": "Cirugía si hay tumor, tratamiento endocrinológico"},
    {"nombre": "Juana Cárdenas", "edad": 55, "grupo_sanguineo": "A-", "diagnostico": "Hipertensión arterial", "sintomas": "Zumbido en los oídos, dificultad para dormir", "tratamiento": "Losartán, Hidroclorotiazida", "recomendaciones": "Monitoreo de presión arterial, control de peso"}
]

# Convertimos a JSON para cifrar como texto
pacientes_json = json.dumps(pacientes)

cifrado = aes_encrypt(pacientes_json, key, iv)
descifrado = aes_decrypt(cifrado, key, iv)
pacientes_descifrados = json.loads(descifrado)

print("\nAES - Mensaje original:")
print(json.dumps(pacientes, indent=2, ensure_ascii=False))

print("\nAES - Cifrado (hex):", cifrado.hex())

print("\nAES - Descifrado:")
print(json.dumps(pacientes_descifrados, indent=2, ensure_ascii=False))


# CRYPTOGRAPHY SCRIPTS TRIAL RSA

# Generar par de claves
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()   
)
public_key = private_key.public_key()

def rsa_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# PRUEBA 2 - RSA

paciente_rsa = "Lucía Ramírez, 65, A+, Hipertensión arterial, Dolor de cabeza, mareo, visión borrosa, Lisinopril, Amlodipino, Reducción de sal, actividad física, control del estrés"

cifrado_rsa = rsa_encrypt(paciente_rsa, public_key)
descifrado_rsa = rsa_decrypt(cifrado_rsa, private_key)

print("\nRSA - Mensaje original:", paciente_rsa)
print("RSA - Cifrado (hex):", cifrado_rsa.hex())
print("RSA - Descifrado:", descifrado_rsa)
print("\nRSA - Mensaje descifrado:", descifrado_rsa)