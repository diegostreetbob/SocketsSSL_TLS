#-------------------------------------------------------------------------------
# Name:        módulo1
# Purpose:
#
# Author:      d7610
#
# Created:     12/04/2020
# Copyright:   (c) d7610 2020
# Licence:     <your licence>
#-------------------------------------------------------------------------------
from OpenSSL import crypto, SSL
from os.path import join
import random
import os
import sys
################################################################################
def generarCertificado():
    CN = "diegoUcamCert"
    CNK = "diegoUcamKey"
    clavepublica = "%s.pem" % CN  #cambio %s con CN
    claveprivada = "%s.pem" % CNK #cambio %s con CNK
    #rutas donde guardar(directorio actual
    clavepublica = join(os.getcwd(), clavepublica)
    claveprivada = join(os.getcwd(), claveprivada)
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048) #rsa 2048 bytes
    serialnumber=random.getrandbits(64)#generación de número de serie aleatorio
    #Creación del certidicado autofirmado
    cert = crypto.X509()
    cert.get_subject().C = "ES"
    cert.get_subject().ST = "Murcia"
    cert.get_subject().L = "Murcia"
    cert.get_subject().O = "Ucam"
    cert.get_subject().OU = "Alumnos"
    cert.get_subject().CN = CN
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(40536000)#tiempo desde hoy en segundos
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512') #hashing sha512
    pub=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    priv=crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    open(clavepublica,"wt").write(pub.decode("utf-8"))
    open(claveprivada,"wt").write(priv.decode("utf-8") )
################################################################################
def main():
    generarCertificado()

if __name__ == '__main__':
    main()
