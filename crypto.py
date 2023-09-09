from flask import Flask, request, jsonify
import rsa
from rsa import PublicKey, PrivateKey
from flask_cors import CORS
from flask_cors import cross_origin


app = Flask(__name__)
cors = CORS(app)



@app.route('/', methods=['GET'])
def hey():
    return "welcome to my application"

@app.route('/generate', methods=['GET'])
def generate():
    publicKey, privateKey = rsa.newkeys(1024)
    n, e, d, p, q = publicKey.n, publicKey.e, privateKey.d, privateKey.p, privateKey.q

    with open("secret.txt", "w") as f:
        f.write(f"{n},{e},{d},{p},{q}")
    return {
        "message" : "Generated keys are", 
        "publicKey" : str(publicKey) , 
        "privateKey" : str(privateKey)
    }

def getKeys():
    data = ""
    with open("secret.txt", "r") as f:
        data = f.read()

    keys = data.split(",")
    keys = list(map(int, keys))

    return keys

@cross_origin()
@app.route('/encrypt', methods=['POST'])
def encrypt():
    keys = getKeys()
    publicKey = PublicKey(keys[0], keys[1])
    
    data = request.get_json()
    message = data['message']

    encMessage = rsa.encrypt(message.encode(), publicKey).hex()

    return {
        "message": encMessage
    }

@app.route('/decrypt', methods=['POST'])
def decrypt():
    keys = getKeys()
    privateKey = PrivateKey(keys[0], keys[1], keys[2], keys[3], keys[4])

    data = request.get_json()
    encMessage = bytes.fromhex(data['encryptedMessage'])
    decMessage = rsa.decrypt(encMessage, privateKey).decode()
    return jsonify({'decryptedMessage': decMessage})

if __name__ == '__main__':
    app.run(debug=True)
