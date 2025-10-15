import PyKCS11
import getpass
from cryptography import x509
from cryptography.hazmat.primitives import serialization 
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives import hashes


lib='C:/Archivos de programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll' # Ruta a la biblioteca PKCS#11 de OpenSC en Windows
pkcs11=PyKCS11.PyKCS11Lib() # Cargar la biblioteca PKCS#11.
pkcs11.load(lib) 

slots=pkcs11.getSlotList(tokenPresent=True) # Obtener la lista de ranuras con tokens presentes.
if not slots:
    print("No se encontraron tokens.")
    exit(1)
print("Slots detectados:", slots)
slot=slots[0] # Seleccionar la primera ranura con un token.

session=pkcs11.openSession(slot) # Abrir una sesión en el slot seleccionado.

pin=getpass.getpass("Introduce el PIN del DNIe: ") # Solicitar el PIN al usuario.

session.login(pin) # Iniciar sesión con el PIN proporcionado.

# Buscar certificados en la tarjeta
certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
if not certs:
    print("No se encontró ningún certificado en el DNIe.")
    exit(1)

# Tomar el primero
cert_obj = certs[0]
# Extraer el valor binario (DER) del certificado
cert_der = bytes(session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE], True)[0])

cert = x509.load_der_x509_certificate(cert_der) # Cargar el certificado en formato x509


with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("Certificado exportado a cert.pem")

print("Información extraida del DNIe")
print(f"Subject: {cert.subject}")
print(f"Issuer: {cert.issuer}")
print(f"Serial_number: {cert.serial_number}")
clave_privada=session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0] # Buscar la clave privada

archivo_firmar=input("Archivo a firmar: ") # Solicitar el archivo a firmar
with open(archivo_firmar, "rb") as f:
    h = hashlib.sha256()
    for chunk in iter(lambda: f.read(1024 * 1024), b""):  # bloques de 1 MB
        h.update(chunk)

digest = h.digest()          # bytes del hash (útil para firmar)
digest_hex = h.hexdigest()   # hash en hex (útil para mostrar/guardar)
print("SHA-256:", digest_hex) # Mostrar el hash en hexadecimal

mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
sig_raw = bytes(session.sign(clave_privada, digest, mechanism)) # Firmar el hash con la clave privada del DNIe 

sig_file = archivo_firmar + ".sig" 
with open(sig_file, "wb") as f: # Guardar la firma en un archivo
    f.write(sig_raw) 
print(f"Firma guardada en: {sig_file}")

clave_publica = cert.public_key() # Extraer la clave pública del certificado


# Leer la firma desde el archivo.
print("Verificamos la firma....")
path_firma=archivo_firmar+".sig"
with open(path_firma, 'rb') as f:
    signature = f.read()

# Verificar la firma
try:
    clave_publica.verify(
        signature,
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Firma verificada correctamente.")
except Exception as e:
    print("Error al verificar la firma:", e)

# Cerrar la sesión
session.logout()
session.closeSession()




