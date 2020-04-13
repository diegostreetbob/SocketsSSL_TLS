
***

<div class="page-break"></div>

***

**Enlace a contenidos:**

[TOC]











<div class="page-break"></div>

***

# 1. Estudio práctico de SSL/TLS

> En esta primera parte del boletín se pide que el alumno analice el funcionamiento de SSL/TLS a través del estudio de una captura de tráfico de las comunicaciones mantenidas por cualquier aplicación instalada en el equipo y que haga uso de este tipo de protección.
>
> Para ello se deberán seguir los siguientes pasos:

## 1. Familiarización con Wireshark.

> Familiarizarse con la herramienta de captura de tráfico Wireshark. Para ello, se ofrece como recurso de ayuda el documento “seminario-wireshark.pdf”, que contiene una breve descripción de las funcionalidades que son necesarias conocer.

Procedo a la revisión del seminario, así como a la descarga de esta versión de *Wireshark*:

![image-20200411103224200](\imagenesP4\image-20200411103224200.png)

Procedo a la instalación y se completa sin mayor problema.

![image-20200411102523032](\imagenesP4\image-20200411102523032.png)

## 2. Captura de tráfico con *Wireshark*.

> Realizar la captura de tráfico sobre el equipo cuando se accede a una página web segura protegida por HTTPS. Por ejemplo, podría valer la captura de tráfico del navegador cuando se realizar el ingreso en nuestra cuenta bancaria online. No obstante, cualquier otro tipo de tráfico será válido siempre y cuando sea protegido.

Realizo una captura del tráfico conectándome a la web de www.google.es y esta es la captura sobre la que analizaré los datos en el siguiente punto:

![image-20200411121918434](\imagenesP4\image-20200411121918434.png)

## 3. Análisis de tráfico capturado.

> Describir la negociación SSL/TLS . Tomando como ejemplo los mensajes SSL/TLS capturados por Wireshark, se pide realizar un análisis descriptivo del proceso de establecimiento de sesión SSL/TLS. Concretamente se pide lo siguiente:

**A. De entre el conjunto de paquetes mostrados por Wireshark, identificar lo mensajes implicados en la negociación. Indicar la fase a la que corresponde cada mensaje.****

1. **Negociación** donde los dos extremos de la comunicación (cliente y servidor) negocian que  algoritmos criptográficos utilizarán para autenticarse y cifrar la  información.

2. **Autenticación y Claves**, donde cliente y servidor se autentican mediante certificados digitales e intercambian las claves para el cifrado, según la  negociación.

   Analizado la información obtenida he llegado a la conclusión de que estos pasos no están 100% separados por lo que contesto los 2 en una misma respuesta.

   

   Línea 45: **Client hello**, en este mensaje, *entre otras cosas*, envía información acerca de la versión *TLS* soportada y las suites criptográficas soportadas.

   ![image-20200411180931235](\imagenesP4\image-20200411180931235.png)

   Línea 47: **Server hello**, y le informa de la versión *TLS* y suite criptográfica elegidas.

   ![image-20200411181053857](\imagenesP4\image-20200411181053857.png)

   Línea 49: El **servidor envía el certificado**, internamente el navegador valida el certificado buscando en su base de CA, su clave pública y la firma y muestra que el trabajo esta terminado mediante **server done**.

   ![image-20200411181513515](\imagenesP4\image-20200411181513515.png)

   ​       ![image-20200411181840570](\imagenesP4\image-20200411181840570.png)

   Línea 51: 

   * El **cliente genera una clave de sesión** cifrada con la clave pública recibida anteriormente del servidor, la clave de sesión es única para cada sesión.
   * Envía el mensaje del tipo *Change Cipher Spec* para hacerle saber que se va a empezar a intercambiar la información cifrada simétricamente del modo previamente pactado.
   * Finaliza esta esta fase.

   ![image-20200411184831247](\imagenesP4\image-20200411184831247.png)

3. Transmisión Segura: los extremos pueden iniciar el tráfico de información cifrada y auténtica.

   Línea 52: la información que se intercambia esta encriptada.

   ![image-20200411190143455](\imagenesP4\image-20200411190143455.png)

**B. Identificar tipo (SSL o TLS) y versión del protocolo empleado.****

La versión de protocolo *TLS* ha sido la 1.2, es decir *TLS1.2*

**C. Averiguar las suites criptográficas negociadas, el método de distribución de claves empleado, así como si la autenticación de cliente es requerida.**

* Suite criptográfica: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* Método de distribución de claves: Diffie Hellman.
* La autenticación del cliente no es requerida.

**D. Analizar cada uno de los mensajes de la negociación, describiendo todos los campos, su valor y el significado de los mismos. Apoyarse en la descripción que muestra Wireshark de los paquetes capturados.**

Explicado en el punto a.





























<div class="page-break"></div>

***

# 2. Sockets seguros en Python.

> En esta segunda parte del boletín el alumno conocerá de primera mano el proceso a seguir para el desarrollo de aplicaciones que hacen uso de comunicaciones de red seguras basadas en SSL/TLS. Tal y como se ha venido haciendo en boletines anteriores, estas aplicaciones se implementarán en un entorno de desarrollo Java, haciendo uso de las librerías que se ofrecen en esta plataforma para la implementación de comunicaciones seguras.

Al igual que el resto de prácticas, previo permiso del profesor, la realizaré en Python.

## Creación de socket seguro en Python.

>  Este es el código empleado para el **servidor**:

```python
# -*- coding: utf-8 -*
#-------------------------------------------------------------------------------
# Name:        server.py
# Purpose:     servidor socket ssl/tls
# Author:      DiegoMGuillén
# Contacto:    dmartinez17@alu.ucam.edu
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
# Contacto:    dmartinez17@alu.ucam.edu
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

![image-20200413073811255](\imagenesP4\image-20200413073811255.png)

Respuesta en la consola del servidor:

![image-20200413074235990](\imagenesP4\image-20200413074235990.png)

### Análisis del tráfico capturado

Esta es la captura realizada con *Wireshark*:

![image-20200413074727400](\imagenesP4\image-20200413074727400.png)

Línea 102: **Client hello**, en este mensaje, *entre otras cosas*, envía información acerca de la versión *TLS* soportada y las suites criptográficas soportadas.

![image-20200413075320821](\imagenesP4\image-20200413075320821.png)

Línea 103: **Server hello**, el servidor contesta con, la versión de *TLS* a usar, suite criptográfica elegida, certificado, clave pública, se usará *Diffie Hellman* para el intercambio de la clave para la parte de criptografía simétrica.

![image-20200413075813769](\imagenesP4\image-20200413075813769.png)

Línea 104:

* El **cliente genera una clave de sesión** cifrada con la clave pública recibida anteriormente del servidor, la clave de sesión es única para cada sesión.
* Envía el mensaje del tipo *Change Cipher Spec* para hacerle saber que se va a empezar a intercambiar la información cifrada simétricamente del modo previamente pactado.
* Finaliza esta esta fase.

![image-20200413080632309](\imagenesP4\image-20200413080632309.png)

Línea 105: El servidor envía la clave de sesión única y desde ahora todas los mensajes intercambiados estarán encriptados mediante *AES* y con la clave simétrica intercambiada.

![image-20200413080844613](\imagenesP4\image-20200413080844613.png)

Línea 106: el cliente envía mensaje encriptado al servidor.

![image-20200413081332283](\imagenesP4\image-20200413081332283.png)

Línea 107: el servidor responde al cliente, el mensaje está encriptado.

![image-20200413081435475](\imagenesP4\image-20200413081435475.png)

<div class="page-break"></div>

***

## Creación de socket **no seguro** en Python.

> Procedo a realizar otro ejemplo que consiste en conectarme con un terminal al un socket **no seguro** y verificar con *Wireshark* que la confidencialidad de los mensajes es nula.

El código del servidor es este:

```python
#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#-------------------------------------------------------------------------------
# Name:        server.py
# Purpose:     servidor socket NO seguro
# Author:      DiegoMGuillén
# Contacto:    dmartinez17@alu.ucam.edu
# Created:     13/04/2020
# Notas:
# Testeado con Python 3.7.6
#-------------------------------------------------------------------------------
################################################################################
from socket import *
import sys
import re
import ssl
import traceback
################################################################################
def main():
    #creación del socket
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.bind((gethostname(), 8801))
    serverSocket.listen(10)
    while True:
        print('1.Activo y preparado para recibir conexiones\n')
        connectionSocket, addr = serverSocket.accept()
        try:
          mensaje = connectionSocket.recv(1024)
          mensajeclte = " _Hola soy tu servidor_"
          print("2.Mensaje recibido desde el cliente: ", mensaje)
          print("3.Respondiendo a cliente con: ", mensajeclte)
          connectionSocket.send(mensajeclte.encode())
          #cerramos la conexión
          connectionSocket.shutdown(SHUT_RDWR)
          connectionSocket.close()
          print("4.Cliente desconectado....\n")
        except IOError:
            connectionSocket.shutdown(SHUT_RDWR)
            connectionSocket.close()
    serverSocket.close()
    sys.exit(0)
################################################################################
if __name__ == '__main__':
    main()
```

Lo ejecutamos desde PowerShell con `py -3 server.py` y esto sería lo que nos muestra una vez enviamos el mensaje desde el terminal.

![image-20200413100611196](\imagenesP4\image-20200413100611196.png)

### Análisis de tráfico capturado

Esta es la captura realizada con *Wireshark*:

<img src="\imagenesP4\image-20200413101252821.png" alt="image-20200413101252821" style="zoom:150%;" />

Donde  vemos los siguiente:

Línea 17: Cliente envía mensaje a servidor, podemos apreciar que el mensaje enviado es totalmente visible.

![image-20200413101509645](\imagenesP4\image-20200413101509645.png)

Línea 18: El servidor responde, y también podemos ver claramente el mensaje enviado por este.

![image-20200413101620093](\imagenesP4\image-20200413101620093.png)



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













