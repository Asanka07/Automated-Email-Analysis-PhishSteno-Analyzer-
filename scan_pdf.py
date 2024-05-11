#!/usr/bin/python3

# Requirements: "pip3 install jsbeautifier"

### Imports

import sys
import os.path
import string
import re
import zlib
import codecs
import jsbeautifier
import PhishStenoAnalyzer as PS

keywords_list = ["/JS ", "/JavaScript"] # to be scanned by find_pattern()
separ_line_len = 60 # number of '-' printed when outputting decoded data

def strings(filename, min=6):
    with open(filename, errors="ignore") as file:
        result = ""
        for c in file.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

def strings_wrapper(filename, min=6):
    for i in strings(filename, min):
        print(i)

def find_pattern(filename, pattern, caseSensitivity=False):
    search_pattern = ""
    if not caseSensitivity:
        search_pattern = "(?i)"
    search_pattern += pattern

    regex = re.compile(search_pattern)
    line_counter = 0
    match_counter = 0
    with open(filename, errors="ignore") as file:
        for line in file:
            line_counter += 1
            for match in re.finditer(regex, line):
                match_counter += 1
                print("[+] Found keyword '"+pattern+"' line "+str(line_counter)+": ", "'"+line[:-1]+"'")

    if not match_counter:
        print("[-] No match found for keyword '"+pattern+"'...")
    else:
        PS.phishing_score_indicator("suspicious_attachments")

def unpack_flatedecode_and_extract_text(filename, txtOnly=False):
    with open(filename, "rb") as file:
        pdf = file.read()

    # FlateDecode-parsing regexes
    flateDecode_headers = re.compile(rb'.*FlateDecode.*').findall(pdf) # regex used to find FlateDecode objects' headers
    flateDecode_data = re.compile(rb'.*?FlateDecode.*?stream([\s\S]*?)endstream', re.S) # regex used to find FlateDecode objects' data

    # Text-parsing regexes
    regex1 = re.compile(rb'\[(.*?)\]') # match everything between [] (step 1)
    regex2 = re.compile(rb'\((.*?)\)') # then match everything between () (step 2)
    
    # Decoding loop
    extracted_text = b''
    i = 0
    for data in flateDecode_data.findall(pdf):
        # if not txtOnly: print("-"*separ_line_len)
        # if not txtOnly: print("[*] Header "+str(i)+":", flateDecode_headers[i])
        # if not txtOnly: print("-"*separ_line_len)
        i += 1
        
        data = data.strip(b'\r\n')

        try:
            dezipped = zlib.decompress(data)
            # if not txtOnly: print("[+] Unpacked data:")
            # if not txtOnly: print("-"*separ_line_len, "\n")
        except:
            # if not txtOnly: print("[-] Zlib couldn't unpack this one. :( Skipping...")
            # if not txtOnly: print("-"*separ_line_len, "\n")
            continue

        # Text extraction
        for stage1 in regex1.findall(dezipped):
            # Pre-processing where we replace characters '(', ')' and '\' by some alias, in order to avoid issues in parsing / matching
            stage1 = stage1.replace(b'\\\\', b'BACK_SLSH')
            stage1 = stage1.replace(b'\\(', b'PAR_OPEN')
            stage1 = stage1.replace(b'\\)', b'PAR_CLOSE')
            
            for stage2 in regex2.findall(stage1):
                extracted_text += stage2

    # Post-processing in final text where we replace aliases by corresponding character (as parsing and matching are now finished we can do it without any issue)
    extracted_text = extracted_text.replace(b'BACK_SLSH', b'\\')
    extracted_text = extracted_text.replace(b'PAR_OPEN', b'(')
    extracted_text = extracted_text.replace(b'PAR_CLOSE', b')')
    return extracted_text

def unpack_javascript(pdf, jsObjectID, extractToFile):
    flateDecode_data = re.compile(jsObjectID + rb' 0 obj[\s\S]*?stream([\s\S]*?)endstream[\s\S]*?obj')

    # Normally, one result only should be returned (so "flateDecode_data.findall(pdf)[0]" would have been sufficient), but just in case there's some problem with the regex it will let us see...
    for content in flateDecode_data.findall(pdf):
        content = content.strip(b'\r\n')
        print("-"*separ_line_len)
        
        try:
            dezipped = zlib.decompress(content)
        except:
            print("[-] Zlib couldn't unpack this JavaScript object. :( Skipping...\n")
            print("-"*separ_line_len, "\n")
            continue

        beautiful_code = jsbeautifier.beautify(dezipped.decode('utf-8'))

        # Write code to file (if option enabled)
        if extractToFile:
            filename = os.path.splitext(os.path.basename(sys.argv[1]))[0]
            filename += "_extracted" + jsObjectID.decode('utf-8') + ".js"
            with open(filename, "w") as file:
                file.write(beautiful_code)
        
        # Print the code
        print("[+] Unpacked code:", beautiful_code)
        print("-"*separ_line_len, "\n")

def spot_extract_javascript(filename, extractToFile=True):
    global noResultFound
    noResultFound = False
    with open(filename, "rb") as file:
        pdf = file.read()
    
    regex1 = re.compile(rb'\/JavaScript[\S\s]*?>>') # pre-match header of all potential JS objects
    regex2 = re.compile(rb'\/JavaScript.*?([1-9][0-9]*).*?>>') # extract object's ID from the header
    regex3 = re.compile(rb'(?<=[<])[0-9A-F]+(?=[>])') # extract inline hexstrings encoded like <HEXSTRING>

    for jsObjectHeader in regex1.findall(pdf):
        
        jsObjectHeader = jsObjectHeader.replace(b'\r', b'').replace(b'\n', b'') # we temporarily remove '\r' and '\n' characters from the header before making the string comparison
        
        # only JS objects ending with "R>>" seems to be unpackable
        if jsObjectHeader[-3:] == b'R>>':
            noResultFound = True
            jsObjectID = regex2.findall(jsObjectHeader)[0]
            print("-"*separ_line_len)
            print("[+] Found JavaScript object number:", jsObjectID.decode('utf-8'))

            unpack_javascript(pdf, jsObjectID, extractToFile)

        # try find hex strings encoded
        hexStrings = regex3.findall(jsObjectHeader)
        if hexStrings:
            noResultFound = True
            for hexStr in hexStrings:
                print("[+] Decoded hex string:\n-----\n%s-----" % bytes.fromhex(hexStr.decode()).decode('utf-8'))

    if  noResultFound:
        print("[-] This contains Malicious content")

def text_postprocessing(text):
    ESCAPE_SEQUENCE_RE = re.compile(r'''
        ( \\U........      # 8-digit hex escapes
        | \\u....          # 4-digit hex escapes
        | \\x..            # 2-digit hex escapes
        | \\[0-7]{1,3}     # Octal escapes
        | \\N\{[^}]+\}     # Unicode characters by name
        | \\[\\'"abfnrtv]  # Single-character escapes
        )''', re.UNICODE | re.VERBOSE)

    def decode_match(match):
        return codecs.decode(match.group(0), 'unicode-escape', errors="ignore")
    
    return ESCAPE_SEQUENCE_RE.sub(decode_match, text)

def isPDFdocument(filename):
    with open(filename, 'rb') as file:
        pdf_begin = file.read(1024) # read only first 1024 bytes
    if b'%PDF' not in pdf_begin:
        return False
    return True

### Main

if __name__ == "__main__":
    # Verifying arguments
    
    if (len(sys.argv) < 2):
        print("Usage:", sys.argv[0].split('\\')[-1], "file-to-scan.pdf")
        exit(1)

    if not os.path.exists(sys.argv[1]):
        print("[!] Error: file doesn't exist")
        exit(1)

    if not isPDFdocument(sys.argv[1]):
        print("[!] Error: this file doesn't seem to be a PDF document")
        print("If you want to scan it anyway (at your own risk), you can remove this disclaimer by deleting the call to isPDFdocument()")
        exit(1)

    # Beginning real work
    print("##### Pattern matching #####\n")
    for keyword in keywords_list:
        find_pattern(sys.argv[1], keyword, False)
        print("")
    print("")

    #

    print("##### Unpack all data (decompress all FlateDecode objects) #####\n")
    extracted_text = unpack_flatedecode_and_extract_text(sys.argv[1], False)
    print("")

    print("##### Extracted text (from dezipped content) #####\n")
    if extracted_text != b'':
        decoded_text = extracted_text.decode("latin1")
        print("[+] Extracted text:", "'"+text_postprocessing(decoded_text)+"'\n")
    else:
        print("[-] This document doesn't contain compressed text\n")
    print("")

    #
    
    print("##### Find and unpack JavaScript code #####\n")
    spot_extract_javascript(sys.argv[1], True)
    print("")

    PS.score()