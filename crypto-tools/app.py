from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from Crypto.Hash import MD5, SHA, SHA224, SHA256, SHA384, SHA512
from Crypto.Cipher import AES, DES
from Crypto.Util import Counter
from Crypto import Random
import pyDH
from os import urandom
import binascii


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/aes')
def aes():
    return render_template('aes.html')

@app.route('/aes/generate', methods=['POST']) #works
def aes_generate():
    bits = request.form['bits']
    key = Random.new().read(int(bits)/8).encode('hex')
    return key

@app.route('/aes/encrypt', methods=['POST']) #works
def aes_encrypt():
    key = request.form['key'].decode('hex')
    bits = request.form['bits']
    mode = request.form['mode']
    plaintext = request.form['message']
    if len(key)==int(bits)/8:
        if len(plaintext) > 0:
            iv = Random.new().read(AES.block_size)
            if (mode == "ECB"):
                cipher = AES.new(key,AES.MODE_ECB, iv) #ECB
                msg = iv + cipher.encrypt(plaintext)
            elif (mode == "CBC"):
                cipher = AES.new(key,AES.MODE_CBC, iv) #CBC
                msg = iv + cipher.encrypt(plaintext)
            elif (mode == "OFB"):
                cipher = AES.new(key,AES.MODE_OFB, iv) #OFB
                msg = iv + cipher.encrypt(plaintext)
            elif (mode == "CTR"):
                ctr = Counter.new(int(bits), initial_value=int(binascii.hexlify(iv), 16))
                cipher = AES.new(key,AES.MODE_CTR, counter=ctr) #CTR
                msg = iv + cipher.encrypt(plaintext)
            return msg.encode('hex')
        flash("Inputs cannot be empty")
        return redirect(url_for('aes'))
    flash("Invalid key length")
    return redirect(url_for('aes'))

@app.route('/aes/decrypt',methods = ['POST'])
def aes_decrypt():
    key = request.form['key'].decode('hex')
    mode = request.form['mode']
    bits = request.form['bits']
    plaintext = request.form['message'].decode('hex')
    iv = plaintext[:AES.block_size]
    plaintext = plaintext[AES.block_size:]
    if len(key) == int(bits)/8:
        if (mode == "ECB"):
            cipher = AES.new(key,AES.MODE_ECB, iv) #ECB
            msg = cipher.decrypt(plaintext)
        elif (mode == "CBC"):
            cipher = AES.new(key,AES.MODE_CBC, iv) #CBC
            msg = cipher.decrypt(plaintext)
        elif (mode == "OFB"):
            cipher = AES.new(key,AES.MODE_OFB, iv) #OFB
            msg = cipher.decrypt(plaintext)
        elif (mode == "CTR"):
            ctr = Counter.new(int(bits), initial_value=int(binascii.hexlify(iv), 16))
            cipher = AES.new(key,AES.MODE_CTR, counter=ctr) #CTR
            msg = cipher.decrypt(plaintext)
        return msg
    flash("Invalid key length")
    return redirect(url_for('aes'))

@app.route('/des', methods=['GET','POST'])
def des():
    return render_template('des.html')

@app.route('/des/generate', methods=['POST']) #works
def des_generate():
    key = Random.new().read(64/8).encode('hex')
    return key

@app.route('/des/encrypt', methods=['POST']) #works
def des_encrypt():
    key = request.form['key'].decode('hex')
    mode = request.form['mode']
    plaintext = request.form['message']
    if len(key)==64/8:
        if len(plaintext) > 0:
            iv = Random.new().read(DES.block_size)
            if (mode == "ECB"):
                cipher = DES.new(key,DES.MODE_ECB, iv) #ECB
                msg = iv + cipher.encrypt(plaintext)
            elif (mode == "CBC"):
                cipher = DES.new(key,DES.MODE_CBC, iv) #CBC
                msg = iv + cipher.encrypt(plaintext)
            elif (mode == "OFB"):
                cipher = DES.new(key,DES.MODE_OFB, iv) #OFB
                msg = iv + cipher.encrypt(plaintext)
            elif (mode == "CTR"):
                ctr = Counter.new(int(bits), initial_value=int(binascii.hexlify(iv), 16))
                cipher = DES.new(key,DES.MODE_CTR, counter=ctr) #CTR
                msg = iv + cipher.encrypt(plaintext)
            return msg.encode('hex')
        flash("Inputs cannot be empty")
        return redirect(url_for('des'))
    flash("Invalid key length")
    return redirect(url_for('des'))

@app.route('/des/decrypt',methods = ['POST'])
def des_decrypt():
    key = request.form['key'].decode('hex')
    mode = request.form['mode']
    plaintext = request.form['message'].decode('hex')
    iv = plaintext[:DES.block_size]
    plaintext = plaintext[DES.block_size:]
    if len(key) == 64/8:
        if (mode == "ECB"):
            cipher = DES.new(key,DES.MODE_ECB, iv) #ECB
            msg = cipher.decrypt(plaintext)
        elif (mode == "CBC"):
            cipher = DES.new(key,DES.MODE_CBC, iv) #CBC
            msg = cipher.decrypt(plaintext)
        elif (mode == "OFB"):
            cipher = DES.new(key,DES.MODE_OFB, iv) #OFB
            msg = cipher.decrypt(plaintext)
        elif (mode == "CTR"):
            ctr = Counter.new(int(bits), initial_value=int(binascii.hexlify(iv), 16))
            cipher = DES.new(key,DES.MODE_CTR, counter=ctr) #CTR
            msg = cipher.decrypt(plaintext)
        return msg
    flash("Invalid key length")
    return redirect(url_for('des'))

@app.route('/rsa', methods=['GET','POST'])
def rsa():
    return render_template('rsa.html')

@app.route('/dh', methods=['GET','POST'])
def dh():
    return render_template('dh.html')

@app.route('/dh/generate')
def dh_generate_public():
    d1 = pyDH.DiffieHellman()
    d1_pubkey = d1.gen_public_key()
    return d1_pubkey


@app.route('/dm', methods = ['GET','POST'])
def dm():
    if request.method == 'POST':
        d1 = pyDH.DiffieHellman()
        d2 = pyDH.DiffieHellman()
        d1_pubkey = d1.gen_public_key()
        d2_pubkey = d2.gen_public_key()
        d1_sharedkey = d1.gen_shared_key(d2_pubkey)
        d2_sharedkey = d2.gen_shared_key(d1_pubkey)
        d1_sharedkey == d2_sharedkey
        return d1_sharedkey
    else:
        return render_template('dh.html')

@app.route('/md5', methods=['GET','POST'])
def md5():
    if request.method == 'POST':
        message = request.form['message']
        if len(message) > 0:
            result = MD5.new(message).hexdigest()
            return render_template('md5.html', result=result)
        else:
            flash("Input cannot be empty")
            return render_template('md5.html')
    return render_template('md5.html')

@app.route('/sha', methods=['GET','POST'])
def sha():
    if request.method == 'POST':
        option = request.form['mode']
        message = request.form['message']
        if len(option) > 0 and len(message) > 0:
            if option == 'SHA':
                msg = SHA.new(message).hexdigest()
            elif option == 'SHA224':
                msg = SHA224.new(message).hexdigest()
            elif option == 'SHA256':
                msg = SHA256.new(message).hexdigest()
            elif option =='SHA384':
                msg = SHA384.new(message).hexdigest()
            elif option == 'SHA512':
                msg = SHA512.new(message).hexdigest()
            return render_template('sha.html', result=msg)
        else:
            flash("Inputs cannot be empty")
            return render_template('sha.html')
    return render_template('sha.html')


if __name__=='__main__':
    app.secret_key = urandom(24)
    #app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///app.db"
    #app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    #if not database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
    #    create_database(app.config['SQLALCHEMY_DATABASE_URI'])

    #db.init_app(app)
    #db.app = app
    #db.create_all()
    #app.db = db
    
    app.run(host='0.0.0.0', port=4000, debug=True)
