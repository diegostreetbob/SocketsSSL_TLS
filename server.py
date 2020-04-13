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
