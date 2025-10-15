import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# ---------------------------
# Configuracion inicial PKCS#11
# ---------------------------
lib = 'C:/Archivos de programa/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll' #ruta a la librería
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList(tokenPresent=True) #obtención de lista de lectores donde hay un token
if not slots:
    raise Exception("No se encontraron tokens.")

#como solo insertamos un lector, elegimos el primero
slot = slots[0] 

session = None
cert = None
clave_privada = None


# ----------------------------
# Acceso al contenido del DNIe
# ----------------------------

#Funcion que autentica al usuario con el PIN del DNIe
def verificar_pin():
    pin = entrada_pin.get()
    try:
        # Abrir sesion y hacer login con el PIN
        global session, cert, clave_privada
        session = pkcs11.openSession(slot)
        session.login(pin)

        # Limpiar inmediatamente el PIN 
        entrada_pin.delete(0, tk.END)
        pin = None  

        # Busqueda de certificado
        certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        if not certs:
            raise Exception("No se encontró ningún certificado en el DNIe.")
       
        #en nuestro caso hemos comprobado que el certificado de firma esta en la tercera posición
        cert_obj = certs[2]
        cert_der = bytes(session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE], True)[0])
        cert = x509.load_der_x509_certificate(cert_der)

        # Buscar clave privada asociada
        cert_id = session.getAttributeValue(cert_obj, [PyKCS11.CKA_ID])[0]
        priv_keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_ID, cert_id)])
        if not priv_keys:
            raise Exception("No se encontró la clave privada correspondiente al certificado.")
        clave_privada = priv_keys[0]

        mostrar_menu()

    except Exception as e:
        messagebox.showerror("Error", str(e)) #Si ocurre cualquier error muestra un mensaje de error



# ----------------------------
# Menu aplicacion
# ----------------------------
def mostrar_menu():
    # Asegura que al cambiar de la pantalla del PIN a la pantalla del menu no se mezclen los widgets antiguos con los nuevos.
    for widget in root.winfo_children():
        widget.destroy()

    # Fondo del menu
    fondo_img = Image.open("fondo.png")  
    fondo_img = fondo_img.resize((600, 400))
    fondo_tk = ImageTk.PhotoImage(fondo_img)

    fondo_label = tk.Label(root, image=fondo_tk)
    fondo_label.image = fondo_tk  # evitar que lo borre el recolector
    fondo_label.place(x=0, y=0, relwidth=1, relheight=1)

    #Titulo del menu
    tk.Label(root, text="Menú principal", font=("Arial", 16, "bold"), bg="#ffffff").pack(pady=20)

    #Botones de accion
    tk.Button(root, text="Exportar certificado", command=exportar_certificado, width=30).pack(pady=5)
    tk.Button(root, text="Firmar documento", command=firmar_documento, width=30).pack(pady=5)
    tk.Button(root, text="Verificar firma", command=verificar_firma, width=30).pack(pady=5)
    tk.Button(root, text="Salir", command=cerrar_sesion, width=30).pack(pady=20)



# ---------------------------
# Funciones principales
# ---------------------------

#Funcion que exporta el certificado del DNIe en formato PEM
def exportar_certificado():
    try:
        # Abre un cuadro de diálogo para elegir el nombre, la ubicación del archivo y obliga al formato .pem
        ruta = filedialog.asksaveasfilename(defaultextension=".pem",filetypes=[("Certificado PEM", "*.pem")],title="Guardar certificado como") 
        if not ruta:
            return
        # Abre el archivo en modo binario y escribe los bytes del certificado en formato PEM
        with open(ruta, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        messagebox.showinfo("Éxito", f"Certificado exportado en: {ruta}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

#Funcion que firma el contenido de un archivo usando la clave privada
def firmar_documento():
    # Abre un cuadro de diálogo para que el usuario seleccione el archivo a firmar
    archivo = filedialog.askopenfilename(title="Selecciona archivo a firmar")
    if not archivo:
        return
    try:
        # Abre el archivo seleccionado en modo binario y lee su contenido
        with open(archivo, "rb") as f:
            data = f.read()
        # Define el mecanismo de firma: RSA con SHA-256
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        # Firma los datos con la clave privada
        sig_raw = bytes(session.sign(clave_privada, data, mechanism))
        # Crea el nombre del archivo de salida agregando la extensión ".sig"
        sig_file = archivo + ".sig"
        # Guarda la firma en un archivo separado
        with open(sig_file, "wb") as f:
            f.write(sig_raw)
        messagebox.showinfo("Éxito", f"Firma guardada en: {sig_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

#Funcion que verifica el archivo .sig comparandoo con el archivo original mediante la clave pública asociada al certificado
def verificar_firma():
    #Archivo original
    archivo = filedialog.askopenfilename(title="Selecciona archivo a verificar")
    if not archivo:
        return
    #Archivo firmado .sig
    sig_file = filedialog.askopenfilename(title="Selecciona archivo .sig")
    if not sig_file:
        return
    try:
        #Leemos datos y firma
        with open(archivo, "rb") as f:
            data = f.read()
        with open(sig_file, "rb") as f:
            signature = f.read()
        #Extraemos la clave pública asociada a ese certificado
        clave_publica = cert.public_key()
        #Verificación
        clave_publica.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        messagebox.showinfo("Verificación", "Firma verificada correctamente.")
    except Exception as e:
        messagebox.showerror("Error", f"Firma no válida: {e}")

#Funcion que cierra sesion en el token y la aplicacion
def cerrar_sesion():
    global session
    if session:
        try:
            session.logout()
            session.closeSession()
        except:
            pass
    root.quit()


# ---------------------------
# Ventana principal
# ---------------------------

root = tk.Tk() #Crea la ventana principal de la aplicacion
root.title("Gestión DNIe") #Titulo de la ventana
root.geometry("750x500") #Tamaño de la ventana

# Fondo de la pantalla de PIN
fondo_img = Image.open("fondo.png")  # carga una imagen con la libreria pillow
fondo_img = fondo_img.resize((750, 500)) #Ajusta el tamaño de la imagen al tamaño de la ventana
fondo_tk = ImageTk.PhotoImage(fondo_img) #Convierte la imagen a un formato compatible con tkinter

#Usa la imagen como fondo de la ventana
fondo_label = tk.Label(root, image=fondo_tk)
fondo_label.image = fondo_tk
fondo_label.place(x=0, y=0, relwidth=1, relheight=1)

tk.Label(root, text="Introduce tu PIN del DNIe:", font=("Arial", 14, "bold"), bg="#ffffff").pack(pady=40)
entrada_pin = tk.Entry(root, show="*", font=("Arial", 14))
entrada_pin.pack(pady=10)
tk.Button(root, text="Acceder", command=verificar_pin, width=20).pack(pady=20) # Al pulsar acceder ejecuta la función verificar_pin

root.mainloop() #mantiene la ventana abierta hasta que el usuario decida cerrarla
