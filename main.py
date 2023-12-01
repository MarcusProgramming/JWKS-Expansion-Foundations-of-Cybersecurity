#Imports necessary libraries
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

#sets the hostname and port the server is hosted on
hostName = "localhost"
serverPort = 8080

#generates a private key, one that will be expired and one that will be valid
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

#converts the expired key and valid key into the pem format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

#converts the private key into private numbers
numbers = private_key.private_numbers()

#initializes the sqlite databse table for keys
database = sqlite3.connect("totally_not_my_privateKeys.db")
cursor = database.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')
database.commit()

#function that converts integers to base 64
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#inserts the expired and unexpired keys into the database, using the time since the unix epoch to find the expiry time
nowtime = datetime.datetime.now()
exptoadd = nowtime.timestamp()
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, int(exptoadd)))
nowtime = datetime.datetime.now()+ datetime.timedelta(hours=1)
exptoadd = nowtime.timestamp()
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, int(exptoadd)))
database.commit()

# Function to retrieve the latest valid key from the database
def get_valid_key():
    cursor.execute("SELECT key FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1", (int(datetime.datetime.now().timestamp()),))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        return None

# Function to retrieve the latest expired key from the database
def get_expired_key():
    cursor.execute("SELECT key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (int(datetime.datetime.now().timestamp()),))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        return None 

#class that handles requests to the server
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self): #PUT requests are forbidden, so it just returns a 405
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self): #PATCH requests are forbidden, so it just returns a 405
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self): #DELETE requests are forbidden, so it just returns a 405
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self): #HEAD requests are forbidden, so it just returns a 405
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self): #For the /auth endpoint, returns a key based on specifications
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth": #Reads a valid key if no expired parameter
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params: #If "expired" is a parameter, returns the expired key
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                key = get_expired_key()
            else:
                key = get_valid_key()

            encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8")) #returns the isnged JWT
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json": #checks if the endpoint is /.well-known/jwks.json
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            valid_key = get_valid_key()
            expired_key = get_expired_key()
            
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": "",
                        "e": "",
                    }
                ]
            }

            
            valid_key = get_valid_key()
            expired_key = get_expired_key()

            if valid_key:
                private_key = serialization.load_pem_private_key(valid_key, password=None, backend=default_backend())
                public_key = private_key.public_key()
                numbers = public_key.public_numbers()
                keys["keys"][0]["n"] = int_to_base64(numbers.n)
                keys["keys"][0]["e"] = int_to_base64(numbers.e)

            
            self.wfile.write(bytes(json.dumps(keys), "utf-8")) #return a dump of all keys there are
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__": #starts hosting the server until the program is terminated
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
