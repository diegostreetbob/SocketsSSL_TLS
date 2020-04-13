# 1. Sockets seguros en Python.

## Creación de socket seguro en Python.

>  Este es el código empleado para el **servidor**:

```python
# -*- coding: utf-8 -*
#-------------------------------------------------------------------------------
# Name:        server.py
# Purpose:     servidor socket ssl/tls
# Author:      DiegoMGuillén
# Contacto:    
# Created:     12/04/2020
# Notas:
# Testeado con Python 2.7.16
#-------------------------------------------------------------------------------
from socket import *
import sys
import re
import ssl
import traceback
################################################################################
diccionario_versiones = {
    "tlsv1.0" : ssl.PROTOCOL_TLSv1,
    "tlsv1.1" : ssl.PROTOCOL_TLSv1_1,
    "tlsv1.2" : ssl.PROTOCOL_TLSv1_2,
}
puerto = 8801
ssl_tls_version = "tlsv1.2"  #usar del diccionario de versiones
certificado = "diegoUcamCert.pem"
clavepublica = "diegoUcamkey.pem"
################################################################################
#Envoltorio del socket en contexto ssl/tls
def wrapSocket(sock, ssl_tls_version, clavepublica, certificado):

    sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    sslContext.load_cert_chain(certificado, clavepublica)

    print "1.Cliente conectado...."

    print "2.Certificado leido: ", certificado, "clavepublica leida", clavepublica

    try:
        return sslContext.wrap_socket(sock, server_side = True)
    except ssl.SSLError as e:
        print "Error...."
        print traceback.format_exc()
################################################################################
def main():
    #creación del socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind((gethostname(), puerto))
    serverSocket.listen(10)
    while True:
        print 'Activo y preparado para recibir conexiones\n'
        newSocket, addr = serverSocket.accept()
        connectionSocket = wrapSocket(newSocket, ssl_tls_version, clavepublica, certificado)
        if not connectionSocket:
            continue
        try:
          mensaje = connectionSocket.recv(1024)
          print "3.Mensaje recibido desde el cliente: ", mensaje
          connectionSocket.send('Hola soy tu servidor....')
          #cerramos la conexión
          connectionSocket.shutdown(SHUT_RDWR)
          connectionSocket.close()
          print "4.Cliente desconectado....\n"
        except IOError:
            connectionSocket.shutdown(SHUT_RDWR)
            connectionSocket.close()
    serverSocket.close()
    sys.exit(0)
################################################################################
if __name__ == '__main__':
    main()
```

> Este es el código empleado para el **cliente**:

```python
# -*- coding: utf-8 -*
#-------------------------------------------------------------------------------
# Name:        client.py
# Purpose:     servidor socket ssl/tls
# Author:      DiegoMGuillén
# Contacto:    
# Created:     12/04/2020
# Notas:
# Testeado con Python 2.7.16
#-------------------------------------------------------------------------------
from socket import *
import sys
import re
import ssl
import pprint
import traceback
################################################################################
puerto = 8801
################################################################################
#Envoltorio del socket en contexto ssl/tls
def wrapSocket(sock):
    sslContext = ssl.create_default_context()
    sslContext.check_hostname = False
    sslContext.verify_mode = ssl.CERT_NONE
    sslContext.load_default_certs()
    try:
        return sslContext.wrap_socket(sock)
    except ssl.SSLError as e:
        print "Error...."
        print traceback.format_exc()
################################################################################
def main():
    #creación del socket
    clientSocket = socket(AF_INET, SOCK_STREAM)
    sslSocket = wrapSocket(clientSocket)
    #sys.argv[1] es la ip del servidor que viene por línea de comandos.
    sslSocket.connect((sys.argv[1],puerto))
    print "1.Me conecto al server...."
    try:
        mensaje = "Hola soy tu cliente"
        print "2.Envio el mensaje: "+ mensaje
        #Enviamos el mensaje
        sslSocket.sendall(mensaje)
        #Recibimos mensaje
        respuesta = sslSocket.recv(1024)
        print "3.Recibo el mensaje: "+ respuesta
    except socket.error:
        #error en envío
        print 'Error....'
        sslSocket.shutdown(SHUT_RDWR)
        sslSocket.close()
    finally:
        #Cerramos el socket si o si.
        print "4.Me desconecto del server"
        sslSocket.close()
################################################################################
if __name__ == '__main__':
    main()
```

> Comunicaciones entre cliente y servidor.

Conexión de cliente a servidor, respuesta en el cliente:

![image-20200413073811255](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413073811255.png)

Respuesta en la consola del servidor:

![image-20200413074235990](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413074235990.png)

### Análisis del tráfico capturado

Esta es la captura realizada con *Wireshark*:

![image-20200413074727400](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413074727400.png)

Línea 102: **Client hello**, en este mensaje, *entre otras cosas*, envía información acerca de la versión *TLS* soportada y las suites criptográficas soportadas.

![image-20200413075320821](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413075320821.png)

Línea 103: **Server hello**, el servidor contesta con, la versión de *TLS* a usar, suite criptográfica elegida, certificado, clave pública, se usará *Diffie Hellman* para el intercambio de la clave para la parte de criptografía simétrica.

![image-20200413075813769](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413075813769.png)

Línea 104:

* El **cliente genera una clave de sesión** cifrada con la clave pública recibida anteriormente del servidor, la clave de sesión es única para cada sesión.
* Envía el mensaje del tipo *Change Cipher Spec* para hacerle saber que se va a empezar a intercambiar la información cifrada simétricamente del modo previamente pactado.
* Finaliza esta esta fase.

![image-20200413080632309](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413080632309.png)

Línea 105: El servidor envía la clave de sesión única y desde ahora todas los mensajes intercambiados estarán encriptados mediante *AES* y con la clave simétrica intercambiada.

![image-20200413080844613](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413080844613.png)

Línea 106: el cliente envía mensaje encriptado al servidor.

![image-20200413081332283](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413081332283.png)

Línea 107: el servidor responde al cliente, el mensaje está encriptado.

![image-20200413081435475](https://github.com/diegostreetbob/SocketsSSL_TLS/blob/master/imagenesP4/image-20200413081435475.png)

<div class="page-break"></div>

***

# Enlaces de interés.

Repositorio para el ejemplo mostrado de sockets seguros: 

https://github.com/diegostreetbob/SocketsSSL_TLS

Repositorio para el ejemplo mostrado de sockets no seguros: 

https://github.com/diegostreetbob/SocketNO_SSL_TLS

# Referencias bibliográficas.

https://docs.python.org/3.7/library/ssl.html



<div class="page-break"></div>













