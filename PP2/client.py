from pickle import FALSE, TRUE
from threading import local
import utilities as util
import socket
'''
PP2 myssl CS-5490
Sam Gera (u1173758)
4/1/22
'''
ID = '[CLIENT]'

if __name__ == "__main__":
    # Prompt user if we want to simulate corrupted or modified msg
    ans = input("Would you like to have the client fail authentication w/ server at hash exchange(y/n)")
    fail_exchange = False
    if(ans == "y"):
        fail_exchange = True
    elif(ans != "n"):
        print("Invalid response\nExiting...")
        quit()

    # create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Send server hello
    m = "Hello from client"
    m = bytes(m, encoding=util.ENCODING)
    
    util.output("Sending message: " + str(m), ID)
    messages = m = util.record_header(m, util.HANDSHAKE) # also start recording messages
    util.initiate(m, server, util.CS_PORT)

    # Wait for hello from server
    m = util.recv_m(server)
    messages += m
    NULL, NULL, NULL, m = util.decode_header(m)

    # wait for certificate
    m = util.recv_m(server)
    messages += m
    NULL, NULL, NULL, cert = util.decode_header(m)

    # Verify certificate
    util.output("Verifying certificate of server", ID)
    util.verify(cert, util.server_keys.public_key())
    
    # Send own certificate
    util.output("Sending own certificate to server", ID)
    cert = util.sign(util.client_keys.public_key(), util.client_keys)
    m = util.record_header(cert, util.HANDSHAKE)
    util.send_m(m, server)
    messages += m
    util.output("Sent certificate to server", ID)

    # Send Data encryption and integrity protection
    standards = "3DES (128-bit) ECB and SHA-1 HMAC".encode(util.ENCODING)
    m = util.record_header(standards, util.HANDSHAKE)
    util.send_m(m, server)
    messages += m
    util.output("Sent standards: %s" % standards.decode(util.ENCODING), ID)
    # Recieve Nonce
    m = util.recv_m(server)
    messages += m
    NULL, NULL, NULL, m = util.decode_header(m)
    R1 = util.decrypt_RSA(m, util.client_keys)
    util.output("Recieved nonce is: %d" % int.from_bytes(R1, 'little'), ID)

    # Generate own nonce
    m = R2 = util.get_ulong()
    util.output("Generated nonce: %d" % int.from_bytes(m, 'little'), ID)
    m = util.encrypt_RSA(m, util.server_keys.public_key())
    m = util.record_header(m, util.HANDSHAKE)
    util.send_m(m, server)
    messages += m 
    util.output("Sent nonce to server", ID)

    # Make the shared secret
    secret = util.make_secret(R1, R2)
    util.output("Shared secret is: %s" % secret, ID)
    util.output("Exiting normally... ", ID)

    # Make the keyed hash of all messages and name
    if(fail_exchange):
        messages += "JUNK".encode(util.ENCODING)
    
    MD = util.HMAC(messages+("CLIENT".encode(util.ENCODING)), secret)
    local_MD = util.HMAC(messages+("SERVER".encode(util.ENCODING)), secret)

    # Exchange hash with server
    m = util.record_header(MD, util.HANDSHAKE)
    util.send_m(m, server)
    util.output("Sent record hash to server", ID)
    remote_MD = util.recv_m(server)
    NULL, NULL, NULL, remote_MD = util.decode_header(remote_MD)

    # Compare Hashes
    util.output("Local HMAC (keyed) is:\n%s" % local_MD, ID)
    util.output("Remote HMAC (keyed) recieved from server is:\n%s" % remote_MD, ID)
    if(local_MD != remote_MD):
        util.output("HMACS did not match. Authentication failed", ID)
        quit()
    util.output("Matched. Authentication successful", ID)

    # Generate a set of 4 16-byte keys
    server_to_client, server_to_clientA, client_to_server, client_to_serverA = util.generate_keys(secret)
    util.output("Generated keys are: ", ID)
    util.output("server->client: %s" % server_to_client, ID)
    util.output("server->client (Auth): %s" % server_to_clientA, ID)
    util.output("client->server: %s" % client_to_server, ID)
    util.output("client->server (Auth): %s" % client_to_serverA, ID)
    
    print("\n\n\n\n\n\n\n\n\n\n\n\n"+ ID + "File Streaming")
    input("Enter any input to being file streaming")
    # Recieve an encrypted file from the server over a stream 
    with open("files\\recieved_bytes_client.txt", mode='wb') as f:
        while TRUE:
            m = util.recv_m(server)

            # Decrypt the message
            m = util.decrypt_ecb(m, server_to_client)

            # Recieve the transfer mode as well as start message
            mode, NULL, NULL, m = util.decode_header(m)


            # Decode the file header to get the file bytes and HMAC
            data, remote_HMAC = util.decode_fheader(m)

            # Compute an HMAC to compare later using the auth key
            local_HMAC = util.HMAC(data, server_to_clientA)

            # Check the HMAC
            util.output("Local HMAC (keyed) is:\n%s" % local_HMAC, ID)
            util.output("Remote HMAC (keyed) recieved from server is:\n%s" % remote_HMAC, ID)
            if(remote_HMAC != local_HMAC):
                util.output("Invalid match between file HMAC and computed", ID)
                util.output("Exiting early!", ID)
                quit()
            
            # Write the bytes to the file
            f.write(data)
          
            # Exit if this was the last packet 
            if(mode == util.FINISHED):
                break


