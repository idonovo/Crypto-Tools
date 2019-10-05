import os
import shutil
from zipfile import ZipFile
from flask import Flask, flash, request, redirect, url_for, render_template, send_file
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature,InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import timedelta


app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
folders = {
    'Archive': 'Archive\\'

}

ALLOWED_EXTENSIONS = set(['pem'])

SHA_DIC={'SHA2' : {
            '224': hashes.SHA224(),
            '256': hashes.SHA256(),
            '384': hashes.SHA384(),
            '512': hashes.SHA512(),
        },
        'SHA3' : {
            '224': hashes.SHA3_224(),
            '256': hashes.SHA3_256(),
            '384': hashes.SHA3_384(),
            '512': hashes.SHA3_512(),
}}

AES_DIC = {
    'CBC':modes.CBC,
    'CTR':modes.CTR,
    'GCM':modes.GCM,
}

def asymmetric_enc_dec(keybuf, text_buf, digest, cipher_file_name, enc):

    hash = hashes.SHA256() if digest == 'SHA256' else hashes.SHA512()

    if enc is True:
        key = serialization.load_pem_public_key(keybuf, backend=default_backend())
        ct = key.encrypt(text_buf, padding.OAEP(mgf=padding.MGF1(algorithm=hash),algorithm=hash,label=None))
    else:
        key = serialization.load_pem_private_key(keybuf,  password=None, backend=default_backend())
        ct = key.decrypt(text_buf, padding.OAEP(mgf=padding.MGF1(algorithm=hash), algorithm=hash, label=None))

    with open(cipher_file_name, 'wb') as filehandle:
        filehandle.write(ct);
        filehandle.close()

    return shutil.move(filehandle.name, folders['Archive'] + filehandle.name)

def verify_sign(inputbuf, keybuf, signbuf, digest, ecosystem):
    pkey = serialization.load_pem_public_key(keybuf ,backend=default_backend())
    hash = hashes.SHA256() if digest == 'SHA256' else hashes.SHA512()

    try:
        if ecosystem == 'RSA':
            pkey.verify( signbuf,inputbuf, padding.PSS( mgf = padding.MGF1(hashes.SHA256())
                                                ,salt_length = padding.PSS.MAX_LENGTH), hash)
        else:
            pkey.verify(signbuf, inputbuf, ec.ECDSA(hash))

    except InvalidSignature:
        return 'Verification Failed'

    return 'Verification Succeed'

def generate_sign(key,input,digest, sign_name, ecosysyem):

    private_key = serialization.load_pem_private_key(
        key,
        password=None,
        backend=default_backend()
    )
    hash =  hashes.SHA256() if digest == 'SHA256' else hashes.SHA512()

    if ecosysyem == 'RSA':
        signature = private_key.sign(input,
                                 padding.PSS( mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),
                                 hash)
    else:
        signature = private_key.sign(input,ec.ECDSA(hash))

    with open(sign_name, 'wb') as filehandle:
        filehandle.write(signature);
        filehandle.close()

    return shutil.move(filehandle.name, folders['Archive'] + filehandle.name)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def key_pair_serilized_and_zipped(private_key, public_key, folder):
    pem_private_key = private_key.private_bytes( encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption())
    pem_public_key = public_key.public_bytes(encoding = serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    paths = [
        folder + '\\private_key.pem',
        folder + '\\public_key.pem'
    ]
    with open(paths[0], 'wb') as  private_file, \
            open(paths[1], 'wb') as  public_file:
        private_file.write(pem_private_key)
        public_file.write(pem_public_key)

    with ZipFile((folder + '.zip'), 'w') as zip:
        # writing each file one by one
        for path in paths:
            zip.write(path)

    shutil.rmtree(folder)
    return shutil.move(zip.filename, folders['Archive'] + zip.filename)

@app.route('/')
def home_page():
    return render_template('index.html')

@app.route('/createDS', methods=['GET', 'POST'])
def DS_sign():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files or 'key' not in request.files:
            flash('No file\key part')
            return redirect(request.url)
        ecosystem = request.form['CryptosystemSelector']
        input = request.files['file']
        key = request.files['key']
        digest = request.form['DigestSelector']
        signature_name =  (request.form['signature_name'] if not request.form['signature_name'] == '' else 'signature') + '.bin'

        #input validation
        if  key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        if input.filename == '':
            flash('No selected input file')
            return redirect(request.url)

        if not allowed_file(key.filename):
            flash('Invalid key format. Valid extensions are: ' + str(ALLOWED_EXTENSIONS))
            return redirect(request.url)

        inputbuff = input.read()
        keybuff = key.read()

        if (str(keybuff).find('BEGIN RSA PRIVATE KEY') != -1 and ecosystem == 'ECC') or\
                (str(keybuff).find('BEGIN EC PRIVATE KEY') != -1 and ecosystem == 'RSA'):
            flash('Wrong key type for chosen cryptosystem')
            return redirect(request.url)

        result = send_file(generate_sign(keybuff,inputbuff, digest, signature_name, ecosystem), as_attachment=True, attachment_filename=signature_name)
        return result
    
    return render_template('createDS.html')

@app.route('/RSAkeypair', methods=['GET', 'POST'])
def generate_RSA_key_pair():
    if request.method == 'POST':
        # check if the post request has the file part
        key_size = request.form['key_sizeSelector']
        key_name = request.form['key_name'] if not request.form['key_name'] == '' else 'key' + key_size

        if not os.path.exists( key_name):
            os.mkdir(key_name)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size= int(key_size), backend=default_backend())
        public_key = private_key.public_key()
        zip_path = key_pair_serilized_and_zipped(private_key, public_key, key_name)
        result = send_file(zip_path, as_attachment=True, attachment_filename=key_name + '.zip')
        return result

    return render_template('RSAkeypair.html')

@app.route('/ECCkeypair', methods=['GET', 'POST'])
def generate_ECC_key_pair():
    if request.method == 'POST':
        # check if the post request has the file part
        key_curve = request.form['curve_Selector']
        key_name = request.form['key_name'] if not request.form['key_name'] == '' else 'key' + key_curve

        if not os.path.exists(key_name):
            os.mkdir(key_name)

        curve = ec._CURVE_TYPES[key_curve]
        ecc_private_key = ec.generate_private_key( curve, default_backend())
        ecc_public_key = ecc_private_key.public_key()

        zip_path = key_pair_serilized_and_zipped(ecc_private_key, ecc_public_key, key_name)
        result = send_file(zip_path, as_attachment=True,
                           attachment_filename=key_name + '.zip')
        return result

    return render_template('ECCkeypair.html')

@app.route('/verifyDS', methods=['GET', 'POST'])
def DS_verify():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files or 'key' not in request.files or 'sign' not in request.files:
            flash('No file\key\sign part')
            return redirect(request.url)
        ecosystem = request.form['CryptosystemSelector']
        input = request.files['file']
        key = request.files['key']
        digest = request.form['DigestSelector']
        sign = request.files['sign']

        #input validation
        if  key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        if input.filename == '':
            flash('No selected input file')
            return redirect(request.url)

        if sign.filename == '':
            flash('No selected signature file')
            return redirect(request.url)


        if not allowed_file(key.filename):
            flash('Invalid key format. Valid extensions are: ' + str(ALLOWED_EXTENSIONS))
            return redirect(request.url)

        inputbuf = input.read()
        keybuf = key.read()
        signbuf = sign.read()

        if (str(keybuf).find('BEGIN RSA PRIVATE KEY') != -1 and ecosystem == 'ECC') or\
                (str(keybuf).find('BEGIN EC PRIVATE KEY') != -1 and ecosystem == 'RSA'):
            flash('Wrong key type for chosen cryptosystem')
            return redirect(request.url)

        res = verify_sign(inputbuf, keybuf, signbuf, digest, ecosystem)
        flash('Verification Result: ' + res)
        return redirect(request.url)

    return render_template('verifyDS.html')

@app.route('/CreateHASH', methods=['GET', 'POST'])
def generate_hash():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)


        input = request.files['file']
        HashSelector = request.form['HashSelector']
        FamilySelector = request.form['FamilySelector']
        hash_file_name = request.form['hash_name'] + '.txt' if not request.form['hash_name'] == '' else FamilySelector + '_'+HashSelector + '.txt'

        if input.filename == '':
            flash('No selected input file')
            return redirect(request.url)

        inputbuf = input.read()
        selected_hash= SHA_DIC[FamilySelector][HashSelector]

        digest = hashes.Hash(selected_hash, backend=default_backend())
        digest.update(inputbuf)

        with open(hash_file_name, 'w+') as hash_file:
            res = digest.finalize().hex()
            hash_file.write(res)

        sha_path = shutil.move(hash_file.name, folders['Archive'] + hash_file.name)
        result = send_file(sha_path, as_attachment=True,
                           attachment_filename=hash_file_name)
        return result

    return render_template('createHASH.html')

@app.route('/CreateHMAC', methods=['GET', 'POST'])
def generate_hmac():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        input = request.files['file']
        key =  request.files['key']
        HashSelector = request.form['HashSelector']
        FamilySelector = request.form['FamilySelector']
        sign_file_name = request.form['sign_name'] + '.txt' if not request.form['sign_name'] == '' else 'HMAC_' + FamilySelector + '_'+ HashSelector + '.txt'

        if input.filename == '':
            flash('No selected input file')
            return redirect(request.url)

        if key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        inputbuf = input.read()
        keybuf = key.read()
        selected_hash= SHA_DIC[FamilySelector][HashSelector]

        h = hmac.HMAC(keybuf, selected_hash, backend=default_backend())
        h.update(inputbuf)

        with open(sign_file_name, 'wb') as sign_file:
            res = h.finalize()
            sign_file.write(res)

        sha_path = shutil.move(sign_file.name, folders['Archive'] + sign_file.name)
        result = send_file(sha_path, as_attachment=True,
                           attachment_filename=sign_file_name)
        return result

    return render_template('CreateHMAC.html')

@app.route('/VerifyHMAC', methods=['GET', 'POST'])
def verify_hmac():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        input = request.files['file']
        key =  request.files['key']
        sign = request.files['sign']
        HashSelector = request.form['HashSelector']
        FamilySelector = request.form['FamilySelector']


        if input.filename == '':
            flash('No selected input file')
            return redirect(request.url)

        if key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        if sign.filename == '':
            flash('No selected signature file')
            return redirect(request.url)

        inputbuf = input.read()
        keybuf = key.read()
        signbuf = sign.read()
        selected_hash= SHA_DIC[FamilySelector][HashSelector]

        h = hmac.HMAC(keybuf, selected_hash, backend=default_backend())
        h.update(inputbuf)
        try:
            h.verify(signbuf)
        except InvalidSignature:
            flash('Verification Failed ')
            return redirect(request.url)

        flash('Verification Succeed')
    return render_template('verifyHMAC.html')

@app.route('/AESkey', methods=['GET', 'POST'])
def generate_AES_key():
    if request.method == 'POST':

        size = request.form['SizeSelector']
        key_file_name = request.form['key_name'] + '.bin' if not request.form['key_name'] == '' else 'AES' + size + '_key.bin'
        with open(key_file_name, 'wb') as key_file:
            key_file.write(os.urandom(int(int(size)/8)))

        key_path = shutil.move(key_file.name, folders['Archive'] + key_file.name)
        result = send_file(key_path , as_attachment=True,
                           attachment_filename= key_file_name)
        return result

    return render_template('AESkey.html')

@app.route('/AESEnc', methods=['GET', 'POST'])
def AES_enc():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'key_name' not in request.files:
            flash('No file part')
            return redirect(request.url)
        if 'IV_name' not in request.files:
            flash('No IV part')
            return redirect(request.url)
        if 'input_name' not in request.files:
            flash('No plain text part')
            return redirect(request.url)

        plain_text = request.files['input_name']
        key = request.files['key_name']
        IV= request.files['IV_name']
        mode = request.form['ModeSelector']

        adata = None
        if 'adata' in request.files:
            adata = request.files['adata']

        cipher_file_name = request.form['output_name'] + '.bin' if not request.form[
                                                                     'output_name'] == '' else 'AES_' + mode + '_cipher_text.bin'
        if  plain_text.filename == '':
            flash('No selected plain text file')
            return redirect(request.url)

        if key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        if IV.filename == '':
            flash('No selected IV file')
            return redirect(request.url)

        plain_text_buf = plain_text.read()
        key_buf = key.read()
        IV_buf = IV.read()

        if( mode != 'GCM'):
            cipher = Cipher(algorithms.AES(key_buf), AES_DIC[mode](IV_buf), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(plain_text_buf) + encryptor.finalize()

        else:
            aesgcm = AESGCM(key_buf)
            ct = aesgcm.encrypt(IV_buf, plain_text_buf, adata.read() if adata != None else None)

        with open(cipher_file_name, 'wb') as ct_file:
            ct_file.write(ct)

        ct_path = shutil.move(ct_file.name, folders['Archive'] + ct_file.name)
        result = send_file(ct_path , as_attachment=True, attachment_filename= cipher_file_name)
        return result

    return render_template('AESEnc.html')

@app.route('/AESDec', methods=['GET', 'POST'])
def AES_dec():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'key_name' not in request.files:
            flash('No file part')
            return redirect(request.url)
        if 'IV_name' not in request.files:
            flash('No IV part')
            return redirect(request.url)
        if 'input_name' not in request.files:
            flash('No cipher text part')
            return redirect(request.url)

        cipher_text = request.files['input_name']
        key = request.files['key_name']
        IV= request.files['IV_name']
        mode = request.form['ModeSelector']
        adata = None
        if 'adata' in request.files:
            adata = request.files['adata']

        plain_file_name = request.form['output_name'] + '.bin' if not request.form[
                                                                     'output_name'] == '' else 'AES_' + mode + '_plain_text.bin'
        if  cipher_text.filename == '':
            flash('No selected cipher text file')
            return redirect(request.url)

        if key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        if IV.filename == '':
            flash('No selected IV file')
            return redirect(request.url)

        cipher_text_buf = cipher_text.read()
        key_buf = key.read()
        IV_buf = IV.read()

        if( mode != 'GCM'):
            cipher = Cipher(algorithms.AES(key_buf), AES_DIC[mode](IV_buf), backend=default_backend())
            decryptor = cipher.decryptor()
            pt =decryptor.update(cipher_text_buf) + decryptor.finalize()
        else:
            aesgcm = AESGCM(key_buf)
            try:
                pt = aesgcm.decrypt(IV_buf, cipher_text_buf, adata.read() if adata != None else None)

            except InvalidTag:
                flash('AES GCM authentication tag failed')
                return redirect(request.url)

        with open(plain_file_name, 'wb') as pt_file:
            pt_file.write(pt)

        pt_path = shutil.move(pt_file.name, folders['Archive'] + pt_file.name)
        result = send_file(pt_path, as_attachment=True, attachment_filename=plain_file_name)
        return result

    return render_template('AESDec.html')

@app.route('/AsymmetricEnc', methods=['GET', 'POST'])
def asymmetric_enc():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'key' not in request.files:
            flash('No key part')
            return redirect(request.url)
        if 'ptext' not in request.files:
            flash('No plain text part')
            return redirect(request.url)

        ptext = request.files['ptext']
        key = request.files['key']
        digest = request.form['DigestSelector']
        cipher_file_name = request.form['ctext_name'] + '.bin' if not request.form['ctext_name'] == '' else 'RSA_cipher_text.bin'

        if  ptext.filename == '':
            flash('No selected plain text file')
            return redirect(request.url)

        if key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        plain_text_buf = ptext.read()
        keybuf = key.read()

        if str(keybuf).find('BEGIN PUBLIC KEY') == -1:
            flash('Wrong key type for chosen operation')
            return redirect(request.url)

        result = send_file(asymmetric_enc_dec(keybuf, plain_text_buf, digest, cipher_file_name, True), as_attachment=True, attachment_filename=cipher_file_name)
        return result

    return render_template('AsymmetricEnc.html')

@app.route('/AsymmetricDec', methods=['GET', 'POST'])
def asymmetric_dec():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'key' not in request.files:
            flash('No key part')
            return redirect(request.url)
        if 'ctext' not in request.files:
            flash('No cipher text part')
            return redirect(request.url)

        ctext = request.files['ctext']
        key = request.files['key']
        digest = request.form['DigestSelector']
        plain_file_name = request.form['ptext_name'] + '.bin' if not request.form['ptext_name'] == '' else 'RSA_plain_text.bin'

        if  ctext.filename == '':
            flash('No selected cipher text file')
            return redirect(request.url)

        if key.filename == '':
            flash('No selected key file')
            return redirect(request.url)

        cipher_text_buf = ctext.read()
        keybuf = key.read()

        if str(keybuf).find('BEGIN RSA PRIVATE KEY') == -1:
            flash('Wrong key type for chosen operation')
            return redirect(request.url)

        result = send_file(asymmetric_enc_dec(keybuf, cipher_text_buf, digest, plain_file_name, False), as_attachment=True, attachment_filename=plain_file_name)
        return result

    return render_template('AsymmetricDec.html')

if __name__ == '__main__':
    app.run()