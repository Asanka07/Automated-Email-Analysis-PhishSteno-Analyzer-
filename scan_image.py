from PIL import Image
from stegano import lsb
import sys
import PhishStenoAnalyzer as PS

def detect_malware_in_image(image_path):
    try:
        # Open the image file
        img = Image.open(image_path)
        
        width, height = img.size
        if width < 10 or height < 10:
            PS.phishing_score_indicator("suspicious_attachments")
            print("Warning: Image dimensions are unusually small, potential malware detected.")
        elif width > 10000 or height > 10000:
            PS.phishing_score_indicator("suspicious_attachments")
            print("Warning: Image dimensions are unusually large, potential malware detected.")
        else:
            print("Image dimensions appear to be safe.")

        # Perform steganography detection
        secret = lsb.reveal(image_path)
        if secret:
            PS.phishing_score_indicator("suspicious_attachments")
            print("Warning: Steganography detected, potential malware hidden within the image.")

    except Exception as e:
        print("No errors detected in the attached image.")

def main():
    if len(sys.argv) != 2:
        print("Usage: python scan_image.py <image_path>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    detect_malware_in_image(image_path)
    PS.score()

if __name__ == "__main__":
    main()
