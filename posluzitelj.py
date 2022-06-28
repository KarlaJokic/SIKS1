# https://github.com/dvatsav/Chat-Room-server
import socket
import os
from x25519 import base_point_mult
from _thread import *
import sys
from cryptography.fernet import Fernet
from konfiguracijska_datoteka import generate_selfsigned_cert as Autentifikacija
from konfiguracijska_datoteka import fernet_kljucic_posluzitelj as fernet_enkripcija
from konfiguracijska_datoteka import fernet_kljucic_klijent as fernet_dekripcija
import konfiguracijska_datoteka


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind(("localhost", 5050))
server.listen(100)


list_of_clients = []

def clientthread(conn, addr):
	while True:
		msg = conn.recv(1024)
		if msg:
			msg = fernet_dekripcija.decrypt(msg)
			print ("Klijent: " + msg.decode('utf-8'))

def posaljithread(conn, addr):
	while True:
		message = bytes(input(), 'utf-8')
		list_of_clients[0].send(fernet_enkripcija.encrypt(message))

while True:

	"""Accepts a connection request and stores two parameters,
	conn which is a socket object for that user, and addr
	which contains the IP address of the client that just
	connected"""
	conn, addr = server.accept()

	"""Maintains a list of clients for ease of broadcasting
	a message to all available people in the chatroom"""
	list_of_clients.append(conn)
	Autentifikacija(socket.gethostname(), 'server', None, None)
	uspjesna_razmjena, poruka = konfiguracijska_datoteka.X25519RazmjenaKljuceva()
	if(uspjesna_razmjena):
		conn.send(fernet_enkripcija.encrypt(poruka))

	# prints the address of the user that just connected
	print (addr[0] + " je spojen")

	# creates and individual thread for every user
	# that connects
	start_new_thread(clientthread,(conn,addr))	
	start_new_thread(posaljithread,(conn,addr))	
conn.close()
server.close()
