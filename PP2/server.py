import utilities as util
import socket

ID = '[SERVER]'
'''
PP2 myssl CS-5490
Sam Gera (u1173758)
4/1/22
'''
if __name__ == "__main__":

    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Attempt to establish server on client-server port
    try:
        server.bind(('localhost', util.CS_PORT))
    except:
        print("Error while binding server socket")
        print("Exiting...")
        quit()
    
    # Wait for hello
    client, m = util.get_connection(server)
    messages = m
    NULL, NULL, NUll, m = util.decode_header(m)

    # Respond with hello & certificate
    m = "Hello, i'm sending certificate!"
    m = bytes(m, encoding=util.ENCODING)
    util.output("Sending hello to client", ID)
    m = util.record_header(m, util.HANDSHAKE)
    util.send_m(m, client)
    messages += m

    # Send certificate
    cert = util.sign(util.server_keys.public_key(), util.server_keys)
    m = util.record_header(cert, util.HANDSHAKE)
    util.send_m(m, client)
    messages += m
    util.output("Sent certificate to client", ID)

    # Recieve and verify client certificate
    m = util.recv_m(client)
    messages += m
    NULL, NULL, NULL, cert = util.decode_header(m)
    
    util.output("Verifying certificate of client", ID)
    util.verify(cert, util.client_keys.public_key())

    # Recieve clients data encryption and integrity protection scheme
    m = util.recv_m(client)
    messages += m
    NULL, NULL, NULL, m = util.decode_header(m)
    util.output("Recieved data encryption and integrity protection is: %s" % m.decode(util.ENCODING), ID)

    # Send encrypted nonce to client
    m = R1 = util.get_ulong()
    util.output("Generated nonce: %d" % int.from_bytes(m, 'little'), ID)
    m = util.encrypt_RSA(m, util.client_keys.public_key())
    m = util.record_header(m, util.HANDSHAKE)
    util.send_m(m, client)
    messages += m
    util.output("Sent nonce to client", ID)

    # Recieve clients encrypted nonce
    m = util.recv_m(client)
    messages += m
    NULL, NULL, NULL, m = util.decode_header(m)
    R2 = util.decrypt_RSA(m, util.server_keys)
    util.output("Recieved nonce is: %d" % int.from_bytes(R2, 'little'), ID)

    # Make the shared secret
    secret = util.make_secret(R1, R2)
    util.output("Shared secret is: %s" % secret, ID)
    util.output("Exiting normally... ", ID)

    # Make the keyed hash of all messages and name (and compute local one to compare)
    MD = util.HMAC(messages + ("SERVER".encode(util.ENCODING)), secret)
    local_MD = util.HMAC(messages + ("CLIENT".encode(util.ENCODING)), secret)

    # Exchange hash w/ client
    m = util.record_header(MD, util.HANDSHAKE)
    remote_MD = util.recv_m(client)
    util.send_m(m, client)
    util.output("Sent record hash to client", ID)
    NULL, NULL, NULL, remote_MD = util.decode_header(remote_MD)

    # Compare Hashes
    util.output("Local HMAC (keyed) is:\n%s" % local_MD, ID)
    util.output("Remote HMAC (keyed) recieved from client is:\n%s" % remote_MD, ID)
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
    # Send a file to the client over a stream
    mode = util.DATA
    with open("files\\random_bytes_server.txt", mode='rb') as f:
        while True:
            data = f.read(util.STREAMSIZE)
            
            # Signal EOS
            if(len(data) < 2000):
                mode = util.FINISHED
                break
            
            # Compute our HMAC and append file header
            hmac = util.HMAC(data, server_to_clientA)
            m = util.encode_fheader(data, hmac)

            # Add our myssl header
            m = util.record_header(m, mode)

            # Encrypt and send
            m = util.form_m(m)

            m = util.encrypt_ecb(m, server_to_client)
            util.send_m(m, client)


