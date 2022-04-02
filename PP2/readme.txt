CS-5490 PP2: myssl
4/1/22
Sam Gera (u1173758)

I've created two python scripts: client.py, and server.py. They perform a mutual handshake using 
the outline of the myssl protocol. Certificates were simply signed public keys (using respective private keys). HMACs of the message history and the shared secret is used for
mutual authentication. This HMAC is computed using SHA1 and and a 64-bit secret. I also implemented a SSL record header
as well as an internal  file header for file streaming. These just maintain fields about the size of the message, the state the 
connection is in, as well as the SSL version (my default was set to 0x300). For file streaming, integrity protection is used as well, using one of the 
auth keys and the file data as functions of the HMAC. I did not have an intelligent key generation function (I couldn't find any I liked), so I decided to write a very naive
one that split up the bits of the master secret to form four distinct keys. utilities.py holds most of the complicated logic for encrypting, integrity protection, header
encode/decode and other things. The scripts just drive the handshake through calling functions within utilities. 

I used pydes and pycryptodome in order to implement most of my cryptographic functions. 