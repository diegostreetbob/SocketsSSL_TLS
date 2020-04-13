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