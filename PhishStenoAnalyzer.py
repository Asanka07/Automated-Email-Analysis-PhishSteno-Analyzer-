import email
from email import policy
from genericpath import exists
import sys
import os
import re
from typing import Final
import colorama
import extract_msg
from colorama import Fore
from stegano import lsb
import requests
import spacy
import json
import language_tool_python
from textblob import TextBlob
from quicksand.quicksand import quicksand
import os
import subprocess

# Load a pre-trained English language model
nlp = spacy.load("en_core_web_md")

API_KEY = 'AIzaSyBL8MvV9Fh_OsLcZQk85qa88RWax_bugsw'
API_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

colorama.init(autoreset=True)

global count

# Initialize LanguageTool
tool = language_tool_python.LanguageTool('en-US')

# Define scoring weights for different indicators
SCORE_WEIGHTS = {
    "suspicious_sender": 3,
    "suspicious_links": 2,
    "suspicious_attachments": 3,
    "phishing_keywords": 1,
    "suspicious_headers": 3
}

# Initialize total_score
total_score = 0

# Function to calculate phishing score based on indicators
def phishing_score_indicator(indicator):
    global total_score  # Access the global total_score variable
    total_score += SCORE_WEIGHTS.get(indicator, 0)

# Path to the JSON file containing phishing-related terms
json_file = "spam_words.json"

        
def load_phishing_terms_from_json(json_file):
    with open(json_file, "r") as f:
        data = json.load(f)
        phishing_terms = data["spam_words"]
    return phishing_terms


# Load phishing terms from JSON
phishing_terms = load_phishing_terms_from_json(json_file)

if len(sys.argv) < 2 or len(sys.argv) > 2:
        exit
else:
        emailFName = sys.argv[1]
        emailFNameF = "Attachments"
        c_path = os.getcwd()
        exportedPath = os.path.join(c_path, emailFNameF)

        try:
            if os.path.exists(exportedPath) is True:
                exit
            else:
                os.mkdir(exportedPath)
        except:
            print("Creating The Path: " + exportedPath)

def grammar_and_spelling_check(email_body):
    # Perform grammar and spelling check
    matches = tool.check(email_body)
    return matches

def preprocess_email_body(email_body):
    # Remove HTML tags
    email_body = re.sub(r'<.*?>', '', email_body)
    # Remove special characters and non-alphanumeric characters
    email_body = re.sub(r'[^a-zA-Z\s]', '', email_body)
    # Convert to lowercase
    email_body = email_body.lower()
    return email_body

def perform_sentiment_analysis(email_body):
    # Perform sentiment analysis using TextBlob
    blob = TextBlob(email_body)
    sentiment_score = blob.sentiment.polarity
    return sentiment_score

def fileChecker():

    if sys.argv[1].endswith('.msg'):
        msgGrabber(sys.argv[1])
    elif sys.argv[1].endswith('.eml'):
        baseGrabber()
    else:
        print(Fore.RED + "The file is in " + sys.argv[1].split(".")[-1] + " format: " + sys.argv[1])

def process_email_body(email_body):
    # Extract phishing-related keywords from the email body
    phishing_keywords = extract_phishing_keywords(email_body , phishing_terms)
    if phishing_keywords:
        print("Phishing-related keywords found:", phishing_keywords)
        phishing_score_indicator("phishing_keywords")

    # Perform grammar and spelling check
    errors = grammar_and_spelling_check(email_body)

    if errors:
        print("Grammar and spelling errors found:")
        for error in errors:
            print(f"Error: {error}")
            phishing_score_indicator("phishing_keywords")
        
    # Preprocess the email body
    preprocessed_body = preprocess_email_body(email_body)

    # Perform sentiment analysis
    sentiment_score = perform_sentiment_analysis(preprocessed_body)

    # Analyze the sentiment score
    if sentiment_score < -0.5:
        print("This email has a highly negative sentiment and may be emotionally manipulative.")
        phishing_score_indicator("phishing_keywords")

def msgGrabber(file):

    try:
        print(Fore.CYAN + "[+] File Name: " + file + "\n")
        with extract_msg.openMsg(file) as messageFile:
            print(Fore.GREEN + "[+] From: " + Fore.RESET + str(messageFile.sender))
            print(Fore.GREEN + "[+] To: " + Fore.RESET + str(messageFile.to))
            print(Fore.GREEN + "[+] Subject: " + Fore.RESET  + str(messageFile.subject))
            print(Fore.GREEN + "[+] CC: " + Fore.RESET  + str(messageFile.cc))
            print(Fore.GREEN + "[+] BCC: " + Fore.RESET  + str(messageFile.bcc))
            print(Fore.GREEN + "[+] Email Time: " + Fore.RESET  + str(messageFile.receivedTime))
            if len(messageFile.attachments) > 0:
                print(Fore.GREEN + "[+] Attachment Found - Saving in Attachments!\n\n")
                for attachment in messageFile.attachments:
                     attachmentName = attachment.getFilename()
                     print(Fore.CYAN + attachmentName + "\n")
                     attachment.save(customPath= exportedPath)
            else:
                print(Fore.GREEN + "[+] No Attachments Observed")
            messageBody = str(messageFile.body)
            trucatedBody = messageBody.replace('\r', ' ')
            print(Fore.GREEN + "[+] Email Body\n\n" + Fore.YELLOW + trucatedBody)

            # Extract phishing-related keywords from the email body
            phishing_keywords = extract_phishing_keywords(trucatedBody, phishing_terms)
            if phishing_keywords:
                print("Phishing-related keywords found:", phishing_keywords)
                phishing_score_indicator("phishing_keywords")

            # Perform grammar and spelling check
            errors = grammar_and_spelling_check(trucatedBody)

            if errors:
                print("Grammar and spelling errors found:")
                for error in errors:
                    print(f"Error: {error}")
                    phishing_score_indicator("phishing_keywords")
            
             # Preprocess the email body
            preprocessed_body = preprocess_email_body(trucatedBody)

            # Perform sentiment analysis
            sentiment_score = perform_sentiment_analysis(preprocessed_body)

            # Analyze the sentiment score
            if sentiment_score < -0.5:
                print("This email has a highly negative sentiment and may be emotionally manipulative.")
                phishing_score_indicator("phishing_keywords")
                

            msgIPGrabber(trucatedBody)
            msgEmailGrabber(trucatedBody)
            msgURLGrabber(trucatedBody)
            messageFile.close()
    except:
        print("Something Went Wrong In msgGrabber!")

def extract_phishing_keywords(email_body, phishing_terms):
    print("Extracting phishing keywords...")
    doc = nlp(email_body)
    phishing_keywords = []

    # Iterate over tokens in the document
    for token in doc:
        # Check if the token has a vector representation and is relevant for phishing terms
        if token.has_vector and token.pos_ in ["NOUN", "VERB", "ADJ", "ADV"]:
            print(f"Token: {token.text}")

            # Initialize a list to store similarity scores for this token with phishing terms
            similarity_scores = []

            # Calculate similarity scores for the token with phishing terms
            for term in phishing_terms:
                if nlp(term).has_vector:
                    similarity_score = token.similarity(nlp(term))
                    similarity_scores.append((term, similarity_score))
            # Filter tokens with high similarity scores
            similar_keywords = [keyword for keyword, score in similarity_scores if score >= 0.6]  # Adjusted threshold
            # print(f"\tSimilar keywords: {similar_keywords}")

            # Add the similar keywords to the list
            phishing_keywords.extend(similar_keywords)

    # Remove duplicates from the list
    phishing_keywords = list(set(phishing_keywords))
    print("Phishing keywords extracted successfully.")
    return phishing_keywords



def msgIPGrabber(bodyWell):

        IP = [] 
        IP_COUNT = 0
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',bodyWell)
        
        try:
            if regex is not None:
                for match in regex:
                    if match not in IP:
                        IP.append(match)
                        IP_COUNT += 1
                        print("\n" + str(IP_COUNT) + Fore.Green + " - IP Address: " + match)
        except:
            print("Something Goes Wrong In Grabbing MSG IPs")

def msgEmailGrabber(emailBody):
        
        EMAIL = [] 
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', emailBody)
        
        try:
            if regex is not None:
                print(Fore.GREEN + "[+] Emails Observed In Email Body\n")
                for match in regex:
                    if match not in EMAIL:
                        EMAIL.append(match)
                        print(match)
            print("\n")
        except:
            print("Something Goes Wrong In Grabbing MSG Emails")

def msgURLGrabber(urlFile):

        try:
            print(Fore.GREEN + "[+] URLs Observed\n\n") 
            URL = [] 
            regex = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',urlFile)
            if regex is not None:
                for match in regex:
                    urlFound = str(match)
                    urlFound = re.sub("[(\']", "", urlFound)
                    urlFound = re.sub(">", "", urlFound)
                    urlFound = re.sub("<", "", urlFound)
                    print(urlFound.strip())
                    check_url(urlFound)
        except:
            print("Something Goes Wrong In MSG URL")


def baseGrabber():
    try: 
        email_subject = ""
        email_body = ""
        print(Fore.BLUE + "-"*50)
        print(Fore.BLUE + "Printing Details You Should Care About!")
        print(Fore.BLUE + "-"*50 + "\n")
        count = 0
        with open(sys.argv[1], "r", encoding="utf-8") as sample:
            for line in sample:
                if line.startswith("From: "):
                    print(Fore.RED + line)
                if line.startswith("To: "):
                    print(Fore.YELLOW + line)   
                if line.startswith("Subject: "):
                    print(Fore.GREEN + line)
                    email_subject = line.split("Subject: ")[1].strip()
                if line.startswith("Date: "):
                    print(Fore.RED + line) 
                if line.startswith("Message-ID: "):
                    print(Fore.GREEN + line)
                if line.startswith("Return-Path:"):
                    print(Fore.YELLOW + line)
                if line.startswith("Return-To:"):
                    print(Fore.GREEN + line)
                if line.startswith("List-Unsubscribe:"):
                    print(Fore.YELLOW + line)
                if line.startswith("Message Body: "):
                    print(Fore.GREEN + line)
                    email_body = line.split("Message Body: ")[1].strip()  # Corrected line
                if line.startswith("Received: "):
                    count += 1

        print("+> Total HOPS Count: " + str(count) + "\n")
        # Process the email body
        process_email_body(email_subject)
        process_email_body(email_body)
        
    except Exception as e:
        print("Something Went Wrong in Base Grabber:", e)
        exit

    finally:
        emailGrabber()


def emailGrabber():
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Butchering Emails!")
    print(Fore.BLUE + "-"*50)

    try:
        fileOpen = open(sys.argv[1],'r', encoding='utf-8')
        readText = fileOpen.read()
        EMAIL = [] 
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', readText)
        if regex is not None:
            for match in regex:
                if match not in EMAIL:
                    EMAIL.append(match)
                    print(Fore.YELLOW + match + "\n")

        
    except:
        print("Something Went Wrong in Email Grabber!")
        exit

    finally:
        ipGrabber()

def ipGrabber():
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Printing The Unique IP Addresses Only!")
    print(Fore.BLUE + "-"*50)
    
    try:
        fileOpen = open(sys.argv[1],'r', encoding='utf-8')
        readText = fileOpen.read()
        IP = [] 
        IP_COUNT = 0
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',readText)
        if regex is not None:
            for match in regex:
                if match not in IP:
                    IP.append(match)
                    IP_COUNT += 1
                    print("\n" + str(IP_COUNT) + Fore.YELLOW + " - IP Address: " + match)
    
    except:
        print("Something Went Wrong IP Grabber!")
        exit
    
    finally:
        urlGrabber()

def check_url(url):
    payload = {
        "client": {
            "clientId": "PhishingEmail",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    params = {'key': API_KEY}
    
    response = requests.post(API_ENDPOINT, params=params, json=payload)
    if response.status_code == 200:
        data = response.json()
        if 'matches' in data:
            # URL is found in Google Safe Browsing API database
            print("URL is potentially malicious")
            phishing_score_indicator("suspicious_links")
        else:
            # URL is not found in Google Safe Browsing API database
            print("URL is safe")
    else:
        # Error handling
        print("Error:", response.status_code)

def urlGrabber():
    print("\n")
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Butchering All The URLs!")
    print(Fore.BLUE + "-"*50 + "\n")
    
    try:
        fileOpen = open(sys.argv[1],'r', encoding='utf-8')
        readText = fileOpen.read()

        # Extract all URLs from the text using the updated regular expression pattern
        urls = re.findall(r'(https?://[^\s<>"]+)', readText)
        
        # Set to store processed URLs
        processed_urls = set()

        # Process each URL
        for url in urls:
            # Check if the URL has already been processed
            if url not in processed_urls:
                # Add the URL to the set of processed URLs
                processed_urls.add(url)
                
                # Print the URL and check its safety
                print(url)
                check_url(url)
        
        if not processed_urls:
            print(Fore.GREEN + "There were no URLs Found!")
    except Exception as e:
        print("Something Went Wrong In URL Grabber:", e)
    
    finally:
        # You may want to call another function or perform additional tasks here
        print("URL Grabber Execution Completed")
        xHunter()
    
def xHunter():
    print("\n")
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Printing All The Headers Which Were Added During The Email Travel")
    print(Fore.BLUE + "-"*50 + "\n")

    try:
        with open(sys.argv[1],'r', encoding='utf-8') as sample:
                for line in sample:
                    if line.startswith("X-"):
                        print(Fore.YELLOW + line)
    except:
        print("No X Headers Observed")
    
    finally:
        embedAttachments()
        

def embedAttachments():
    print(Fore.BLUE + "-"*50)
    print(Fore.BLUE + "Checking If There Are Any Attachments")
    print(Fore.BLUE + "-"*50)

    try:
        with open(sys.argv[1], "r") as f:
            emailFNameF = "Attachments"
            c_path = os.getcwd()
            exportedPath = os.path.join(c_path, emailFNameF)
            attachments_found = False
            attachFile = email.message_from_file(f, policy=policy.default)
            for attachment in attachFile.iter_attachments():
                attName = attachment.get_filename()
                attachments_found = True
                print(Fore.GREEN + "\n[+] File Found & Written In Attachments: " + Fore.RESET + attName)
                with open(os.path.join(exportedPath, attName), "wb") as fileWrite:
                    # print("here 3")
                    fileWrite.write(attachment.get_payload(decode=True))
                detectSteganography(os.path.join(exportedPath, attName))

            if not attachments_found:
                print("No attachments found.")
                score()   
            
    except:
        print("Something Went Wrong In Embed Attachments")


def detectSteganography(file_path):
    # Check if the file exists
    if os.path.exists(file_path):
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension == '.pdf':
            # Call scan_pdf.py with file path and name
            subprocess.run(['python', 'scan_pdf.py', file_path])
        elif file_extension in ('.png', '.jpg', '.jpeg', '.bmp'):
            # Call scan_image.py with file path and name
            subprocess.run(['python', 'scan_image.py', file_path])
        elif file_extension == '.gif':
            # Call scan_GIF.py with file path and name
            subprocess.run(['python', 'scan_GIF.py', file_path])
        else:
            print("Unsupported file type:", file_path)
    else:
        print("File not found:", file_path)

def score ():
        # Once all checks are done, print the total score for the email
    print(Fore.YELLOW + "Total Score for the Email: ", total_score)

    # Determine if the email is phishing based on the total score
    if total_score >= 6:
        print(Fore.RED + "This email is highly suspicious and may be a phishing attempt!")
    elif total_score >= 3:
        print(Fore.YELLOW + "This email has some suspicious elements. Use caution!")
    else:
        print(Fore.GREEN + "This email appears to be legitimate.")

def banner():

    banner = """
    
    Automated Email Analysis for Phishing Detection and Steganography Recognition
    Developed by Asanka Jayaweera
    -----------------------------------------
    This tool helps in detecting phishing emails and analyzing for steganography.
    Usage: PhishStenoAnalyzer.py <options>
    -----------------------------------------
    """

    print(Fore.GREEN + banner + "\n")

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 2:
        print(Fore.YELLOW + "Invalid number of arguments provided!")
    else:
        fileChecker()

    # score()

if __name__ == "__main__":
    main()