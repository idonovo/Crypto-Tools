import os
import shutil
from zipfile import ZipFile
from flask import Flask, flash, request, redirect, url_for, render_template, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
folders = {
    'UPLOAD_FOLDER': 'D:\CryptoTools\Crypto-Tools\Temp\\',
    'Archive' : 'Archive\\'

}

ALLOWED_EXTENSIONS = set(['pem'])
app.config['UPLOAD_FOLDER'] = folders['UPLOAD_FOLDER']

def generate_sign(key,input,digest, sign_name, ecosysyem):

    private_key = serialization.load_pem_private_key(
        key,
        password=None,
        backend=default_backend()
    )
    hash =  hashes.SHA256() if digest == 'Sha256' else hashes.SHA512()

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
    return render_template('base.html')

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
        raw_key = ecc_private_key.private_bytes( encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption())

        zip_path = key_pair_serilized_and_zipped(ecc_private_key, ecc_public_key, key_name)
        result = send_file(zip_path, as_attachment=True,
                           attachment_filename=key_name + '.zip')
        return result

    return render_template('ECCkeypair.html')


if __name__ == '__main__':
    app.run(port=5000, debug=True)