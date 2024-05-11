from flask import Flask, render_template, request, redirect, url_for
import os
import sys
from io import StringIO
import PhishStenoAnalyzer
import subprocess

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            return redirect(request.url)
        
        if file:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Create a StringIO object to capture the output
            output = StringIO()
            sys.stdout = output  # Redirect stdout
            sys.stderr = output  # Redirect stderr

            try:
                # Run PhishStenoAnalyzer.py as a subprocess
                process = subprocess.Popen(['python', 'PhishStenoAnalyzer.py', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                output_text = stdout.decode() + stderr.decode()
            except Exception as e:
                output_text = str(e)

            # Reset stdout and stderr
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            
            return render_template('index.html', output=output_text)

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
