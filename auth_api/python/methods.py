import hashlib

import jwt
import mysql.connector
from flask import request, make_response

# These functions need to be implemented
class Token:
    secret = 'my2w7wjd7yXF64FIADfJxNs1oupTGAuW'
    def generate_token(self, username, password):
        try:
            pa, se, ro = get_enscript_pass(username)
        except:
            return make_response('HTTP error message', 403, {'WWW-Authenticate': 'Invalid user'})

        key = password+se
        passcript = hashlib.sha512(str(key).encode("utf-8")).hexdigest()

        if passcript==pa:
            token = jwt.encode(
                headers={"alg": "HS256", "typ": "JWT"},
                payload = {"role":ro},
                key=self.secret,
                algorithm='HS256'
            )
        
            return token
        else:
            return make_response('HTTP error message', 403, {'WWW-Authenticate': 'Invalid credentials'})

class Restricted:
    secret = 'my2w7wjd7yXF64FIADfJxNs1oupTGAuW'
    def access_data(self, authorization):
        
        aut = authorization.split(' ')[1]
        try :
            val = jwt.decode(aut, self.secret, algorithms=['HS256'])
        except:
            val = {} 
            val["role"] = False
        
        if val["role"]:
            return 'You are under protected data'
        else :
            return '401'

def connect_to_db():
    user = "secret"
    passw = "noPow3r"
    host = "bootcamp-tht.sre.wize.mx"
    db = "bootcamp_tht"

    mydb = mysql.connector.connect(
        host=host,
        user=user,
        password=passw, 
        db=db
    )
    return mydb

def get_enscript_pass(username):
    conn = connect_to_db()
    cur = conn.cursor()
    cur.execute("SELECT password, salt, role FROM users WHERE username='"+username+"'")
    res = cur.fetchone()
    conn.close()
    return res