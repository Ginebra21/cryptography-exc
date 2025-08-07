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
    {"Andrés Torres	60	O-	Diabetes tipo 2	Pérdida de peso, visión borrosa	Insulina, Glibenclamida	Monitoreo glucémico intensivo, cambio en hábitos alimenticios"},
    {"Carlos Méndez	58	O+	Diabetes tipo 2	Fatiga, sed excesiva, visión borrosa	Metformina, Insulina	Control glicémico, dieta baja en carbohidratos, ejercicio regular"},
    {"Diego Londoño	29	A+	Miastenia gravis	Debilidad muscular, visión doble	Piridostigmina, Corticoides	Terapia inmunosupresora, ejercicios de respiración"},
    {"Elena Vargas	43	B+	Asma	Sibilancias, dificultad para respirar	Formoterol, Fluticasona	Terapia broncodilatadora, evitar factores desencadenantes"},
    {"Isabela Fonseca	41	B+	Síndrome de Cushing	Obesidad central, cara redonda	Ketoconazol, Mifepristona	Cirugía si hay tumor, tratamiento endocrinológico"},
    {"Juan  a Cárdenas	55	A-	Hipertensión arterial	Zumbido en los oídos, dificultad para dormir	Losartán, Hidroclorotiazida	Monitoreo de presión arterial, control de peso"},
    {"María Gómez	50	AB+	Asma	Dificultad para respirar, tos	Salbutamol, Budesonida	Inhaladores, evitar alérgenos, terapia respiratoria"},
    {"Pedro Acosta	72	B-	Colesterol alto	Dolor en el pecho, fatiga	Atorvastatina	Dieta baja en grasas, ejercicio aeróbico, monitoreo regular"},
    {"Samuel Ríos	68	AB-	Colesterol alto	Fatiga, dolor en piernas	Rosuvastatina	Mejorar dieta, evitargrasas saturadas, ejercicio regular"},
    {"Tomás Herrera	52	AB-	Esclerosis lateral amiotrófica	Debilidad muscular progresiva	Riluzol, Edaravona	Rehabilitación, fisioterapia, asistencia respiratoria"},
    {"Valentina Duarte	35	O+	Síndrome de Ehlers-Danlos	Hiperflexibilidad, dolor articular	Analgésicos, suplementos de colágeno	Fisioterapia, uso de ortesis, monitoreo genético"}

# Se debe convertir la información a JSON para cifrar como texto
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

# Generar par de claves cifrado y descifrado
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

# PRUEBA 2 - RSA. Al ser un proceso más lento, éste no permite un cifrado de información de gran escala

paciente_rsa = "Lucía Ramírez, 65, A+, Hipertensión arterial, Dolor de cabeza, mareo, visión borrosa, Lisinopril, Amlodipino, Reducción de sal, actividad física, control del estrés"

cifrado_rsa = rsa_encrypt(paciente_rsa, public_key)
descifrado_rsa = rsa_decrypt(cifrado_rsa, private_key)

print("\nRSA - Mensaje original:", paciente_rsa)
print("RSA - Cifrado (hex):", cifrado_rsa.hex())
print("RSA - Descifrado:", descifrado_rsa)
print("\nRSA - Mensaje descifrado:", descifrado_rsa)
