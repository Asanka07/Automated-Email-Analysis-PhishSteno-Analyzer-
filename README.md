# Automated-Email-Analysis-PhishSteno-Analyzer-
A designed solution to automatically detect and mitigate phishing and steganography threats within email communications, ensuring the protection of sensitive information and the integrity of digital networks.

This Flask web application allows users to upload email files for automated analysis to detect phishing attempts and analyze steganographically embedded content. The application utilizes the `PhishStenoAnalyzer` script to perform the analysis and provides the output to the user.

## Usage
1. Access the web application through the browser.
2. Upload an email file using the provided file upload interface.
3. The application will analyze the uploaded file automatically.
4. The analysis results, including detected threats and potential risks, will be displayed to the user.
5. Users can review the output and take necessary actions based on the findings.

## Features
- **File Upload:** Allows users to upload email files for analysis.
- **Automated Analysis:** Utilizes the `PhishStenoAnalyzer` script to perform automated analysis.
- **Output Display:** Displays the analysis results, including detected threats and potential risks, to the user.
- **Error Handling:** Provides error handling to ensure smooth operation of the application.
- **Web Interface:** Offers a user-friendly web interface for easy interaction.

## Dependencies
- `Flask`: For building the web application
- `PhishStenoAnalyzer`: Script for phishing detection and steganalysis
- `subprocess`: For running the `PhishStenoAnalyzer` script as a subprocess
- `os`: For file and path operations
- `sys`: For capturing stdout and stderr
- `io`: For creating StringIO object to capture output
- `colorama`: For colored terminal output
- `extract_msg`: For extracting data from Outlook MSG files
- `stegano`: For steganography detection in images
- `requests`: For making HTTP requests to Google Safe Browsing API
- `spacy`: For natural language processing tasks
- `language_tool_python`: For grammar and spelling checks
- `textblob`: For sentiment analysis

## Deployment
1. Install the required dependencies using pip:
    ```
    pip install flask
    ```
2. Run the Flask application:
    ```
    python app.py
    ```
3. Access the web application through the provided URL (usually http://127.0.0.1:5000/) in a web browser.

