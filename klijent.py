'''
Kod za komunikaciju preko socketa je preuzet sa https://www.geeksforgeeks.org/simple-chat-room-using-python/
'''

import socket
import os
from _thread import *
import select
from konfiguracijska_datoteka import fernet_kljucic_posluzitelj as fernet_dekripcija
from konfiguracijska_datoteka import fernet_kljucic_klijent as fernet_enkripcija
from numpy import polyder
from x25519 import base_point_mult
import sys
from konfiguracijska_datoteka import generate_selfsigned_cert as Autentifikacija
import konfiguracijska_datoteka

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP_address = "localhost"
Port = 5050
server.connect((IP_address, Port))
Autentifikacija(socket.gethostname(), 'klijent', None, None)

while True:
	# maintains a list of possible input streams
	sockets_list = [sys.stdin, server]
	read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])
	for socks in read_sockets:
		if socks == server:
			msg = socks.recv(1024)
			if msg:
				msg = fernet_dekripcija.decrypt(msg)
				print ("Posluzitelj: " + msg.decode('utf-8'))
		else:
			message = bytes(input(), 'utf-8')
			msg = fernet_enkripcija.encrypt(message)
			server.send(msg)
			sys.stdout.flush()
server.close()
