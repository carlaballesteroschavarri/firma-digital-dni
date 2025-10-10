# firma-digital-dni
Es una aplicación de Python que nos permite firmar y verificar archivos mediante el uso del DNI vía PKCS#11. Incluye una interfaz gráfica sencilla (Tkinter) con tres acciones: Firmar, Verificar y Exportar certificado, pensada para que cualquier usuario pueda usar el DNIe sin línea de comandos. 
La firma se ejecuta dentro del chip del DNIe, por lo que la clave privada nunca sale del token. Al firmar se genera, junto al fichero original, un archivo.sig basado en RSA-PKCS#1 v1.5 y SHA-256. 
La verificación comprueba que el .sig corresponde exactamente al archivo original usando la clave pública del certificado.
La opción Exportar certificado guarda el X.509 en PEM, útil para compartir la clave pública o para verificaciones externas.
El PIN se pide con entrada oculta, se borra tras el login, y al salir se cierra la sesión PKCS#11. Para poder utilizar la aplicación necesitarás un lector de DNIs y el DNI, tener OpenSC instalado y ruta válida al módulo opensc-pkcs11. 
