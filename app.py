import os
from flask import Flask, flash, request, redirect, url_for, render_template, send_file
from werkzeug.utils import secure_filename
import OpenSSL.crypto


app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
UPLOAD_FOLDER = 'D:/CryptoTools'
ALLOWED_EXTENSIONS = set(['pem'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def generate_rsa_sign(key,input, digest):
    c = OpenSSL.crypto
    t_key = open(key, 'rt').read()
    pkey = c.load_privatekey(c.FILETYPE_PEM, t_key)
    sign =c.sign(pkey, open(input, 'rt').read(), digest)
    filehandle = open(os.path.dirname(os.path.abspath(input)) + '\output', 'wb')
    filehandle.write(sign);
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

        # if user does not select file, browser also
        # submit an empty part without filename
        if input.filename == '' or key.filename == '':
            flash('No selected files')
            return redirect(request.url)
        if not allowed_file(key.filename):
            flash('Invalid key format. Valid extensions are: ' + str(ALLOWED_EXTENSIONS))
            return redirect(request.url)

        inputfilename = secure_filename(input.filename)
        input.save(os.path.join(app.config['UPLOAD_FOLDER'] +'/RSA_FOLDER', inputfilename))
        keyfilename = secure_filename(key.filename)
        key.save(os.path.join(app.config['UPLOAD_FOLDER'] + '/RSA_FOLDER', keyfilename))
        output = generate_rsa_sign(os.path.join(app.config['UPLOAD_FOLDER'] + '/RSA_FOLDER', keyfilename), os.path.join(app.config['UPLOAD_FOLDER'] +'/RSA_FOLDER', inputfilename), digest)
        return send_file(output.name)
    
    return render_template('rsa.html')

if __name__ == '__main__':
    app.run(port=5000, debug=True)