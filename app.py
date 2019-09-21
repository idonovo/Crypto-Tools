import os
import glob
from flask import Flask, flash, request, redirect, url_for, render_template, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
folders = {
    'UPLOAD_FOLDER': 'D:\CryptoTools\Crypto-Tools\Temp\\',
    "TSA" : '/RSA_FOLDER'
}

ALLOWED_EXTENSIONS = set(['pem'])
app.config['UPLOAD_FOLDER'] = folders['UPLOAD_FOLDER']

def generate_rsa_sign(key,input, digest):

    private_key = serialization.load_pem_private_key(
        key.read(),
        password=None,
        backend=default_backend()
    )
    hash =  hashes.SHA256() if digest == 'Sha256' else hashes.SHA512()
    signature = private_key.sign(input.read(),
                                 padding.PSS( mgf = padding.MGF1(hashes.SHA256()),salt_length = padding.PSS.MAX_LENGTH),
                                 hash)
    filehandle = open(os.path.join(app.config['UPLOAD_FOLDER'], 'output'), 'wb')
    filehandle.write(signature);
    filehandle.close()
    return filehandle


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home_page():
    return render_template('base.html')

@app.route('/rsa', methods=['GET', 'POST'])
def RSA_sign():


    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files or 'key' not in request.files:
            flash('No file\key part')
            return redirect(request.url)
        input = request.files['file']
        key = request.files['key']
        digest = request.form['DigestSelector']
        signature_name =  request.form['signature_name'] if not request.form['signature_name'] == '' else 'signature'

        # if user does not select file, browser also
        # submit an empty part without filename
        if input.filename == '' or key.filename == '':
            flash('No selected files')
            return redirect(request.url)
        if not allowed_file(key.filename):
            flash('Invalid key format. Valid extensions are: ' + str(ALLOWED_EXTENSIONS))
            return redirect(request.url)

        inputfilename = secure_filename(input.filename)
        input.save(os.path.join(app.config['UPLOAD_FOLDER'], inputfilename))
        keyfilename = secure_filename(key.filename)
        key.save(os.path.join(app.config['UPLOAD_FOLDER'] , keyfilename))

        with open(app.config['UPLOAD_FOLDER'] + keyfilename, "rb") as key:
            with open(app.config['UPLOAD_FOLDER'] +inputfilename, "rb") as input:
                result = send_file(generate_rsa_sign(key,input, digest).name, as_attachment=True, attachment_filename=signature_name)
        os.remove(app.config['UPLOAD_FOLDER'] + keyfilename)
        os.remove(app.config['UPLOAD_FOLDER'] +inputfilename)
        return result
    
    return render_template('rsa.html')

if __name__ == '__main__':
    app.run(port=5000, debug=True)