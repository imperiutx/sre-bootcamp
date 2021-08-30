from flask import Flask
from flask import jsonify
from flask import request, make_response
from werkzeug.datastructures import WWWAuthenticate
from methods import Token, Restricted, db

app = Flask(__name__)
login = Token()
protected = Restricted()

# Just a health check
@app.route("/")
def url_root():
    return jsonify({"data": "OK"})

# Just a health check
@app.route("/_health")
def url_health():
    return "OK"

# e.g. http://127.0.0.1:8000/login
@app.route("/login", methods=['POST'])
def url_login():
    username = request.form['username']
    password = request.form['password']
    res = login.generate_token(username, password)
    return jsonify({"data": res})

# # e.g. http://127.0.0.1:8000/protected
@app.route("/protected")
def url_protected():
    auth_token = request.headers.get('Authorization')
    res = protected.access_data(auth_token)
    if res=='401':
        return make_response('Forbidden', 401, {'WWW-Authenticate': 'Invalid token'})
    else :
        return jsonify({"data": res})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
