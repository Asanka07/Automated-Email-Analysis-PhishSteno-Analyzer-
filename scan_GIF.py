import binascii
import sys
import PhishStenoAnalyzer as PS

#Function to display warning message
def unsafe():
    PS.phishing_score_indicator("suspicious_attachments")
    print("Warning!!! This Gif is not safe.")
    

#Function to skip the extension blocks
def extension(idx):
    idx = idx+2                             #Skip 21h

    while True:

        if hexc[idx:idx+2] == 'f9':         #Graphics controller extension
            idx = idx+14                    #Skip the rest of the extension block

        if hexc[idx:idx+2] == '01':         #Plain Text extension
            s = int(hexc[idx+2:idx+4],16)   #Calculate the number of bytes to skip
            idx = idx+2
            idx = idx+(s*2)                 #Skip the rest of the extension. After this, there will be an image data block.
            return idx

        if hexc[idx:idx+2] == 'ff':         #Application extension
            s = int(hexc[idx+2:idx+4],16)   #Calculate the number of bytes to skip
            idx = idx+2
            idx = idx+(s*2)                 #Skip the rest of the extension. After this, there will be an image data  block.
            return idx

        if hexc[idx:idx+2] == 'fe':         #Comment extension
            idx = idx+2
            return idx                      #After this, there will be an image data block.

        if hexc[idx:idx+2] == '2c':         #Image separator
            packed = hexc[idx+18:idx+20]    #Packed field
            packed = "{0:08b}".format(int(packed, 16))
            LCT = 0                         #Number of Local colour table entries

            if(packed[7] == '1'):           #If Local colour table exists
                N = int(packed[0:3],2)
                N = N+1
                LCT = pow(2,N)              #Calculate number of Local colour table entries
            
            idx = idx+20                    #Skip Image descriptor
            idx = idx+(3*LCT)               #Skip local colour table
            idx = idx+2                     #Skip LZW minimum code size
            return idx


if __name__ == "__main__":
    if (len(sys.argv) < 2):
        print("Usage: python script_name.py <image_path>")
        sys.exit(1)
    
    filename = sys.argv[1]

    try:
        with open(filename, 'rb') as f:
            content = f.read()
    except IOError:
        print("File not found!")
        sys.exit()


    hexc = binascii.hexlify(content)        #Load the Hexadecimal version of the GIF file 
    hexc = hexc.decode("utf-8")


    if(hexc[0:4] != '4749'):                #Check file type
        print("The file is not a gif")
        sys.exit()

    if(hexc[8:12] != '3961'):               #Check GIF file version. We support only GIF version 89a
        print("The file is not an 89a gif")
        sys.exit()

    packed = hexc[20:22]                    #Packed field of the Logical Screen Descriptor
    packed = "{0:08b}".format(int(packed, 16))
    GCT = 0                                 #Number of Global colour table entries

    if(packed[0] == '1'):                   #If Global colour table exists
        N = int(packed[5:8],2)
        N = N+1
        GCT = pow(2,N)                      #Calculate number of Global colour table entries

    skip = (6*2)+(7*2)+(3*GCT)              #Skip header, logical screen descriptor and global colour table
    idx = skip


    while True:

        if hexc[idx:idx+2] == '2c':         #Image separator
            packed = hexc[idx+18:idx+20]    #Packed field
            packed = "{0:08b}".format(int(packed, 16))
            LCT = 0                         #Number of Local colour table entries

            if(packed[7] == '1'):           #If Local colour table exists
                N = int(packed[0:3],2)
                N = N+1
                LCT = pow(2,N)              #Calculate number of Local colour table entries
            
            idx = idx+20                    #Skip Image descriptor
            idx = idx+(3*LCT)               #Skip local colour table
            idx = idx+2                     #Skip LZW minimum code size

        if hexc[idx:idx+2] == '3b':         #Trailer
            break
    
        elif hexc[idx:idx+2] == '21':       #Extension block
            idx = extension(idx)            #Skip extension blocks

        else:                               #Image data blocks
            while hexc[idx:idx+2] != '00':  #While block size not equal to zero
                s = int(hexc[idx:idx+2],16) #Number of bytes to skip
                idx = idx+2
                idx = idx+(s*2)
            idx = idx +2

    if(len(hexc) != idx+2):     #If there exists some data after the trailer 0x3b
        unsafe()
        PS.score()
    else:
        print("This Gif is safe to use")
        PS.score()

    