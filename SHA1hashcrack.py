import hashlib
from urllib.request import urlopen
#PROOF OF CONCEPT FOR CRACKING PASSWORDS HASHED WITH SHA1 HASH
#Casts the user supplied password into a sha1 hash and stores it for cracking
def sha1_hash(setpass):
    bytespass = bytes(setpass, 'utf-8')
    hash_object = hashlib.sha1(bytespass)
    hex_dig = hash_object.hexdigest()
    return(hex_dig)
#TRIES PASSWORDS OR HASHES AGAINST LIST OF 10,000 WORST PASSWORDS
def try_worst_passwords(origin):
    textpage = urlopen(
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt')
    LIST_OF_COMMON_PASSWORDS = str(textpage.read(), 'utf-8')
    for password in LIST_OF_COMMON_PASSWORDS.split('\n'):
        setpass = bytes(password, 'utf-8')
        hash_object = hashlib.sha1(setpass)
        guess_pw = hash_object.hexdigest()
        if guess_pw == origin:
            print("The password is ", str(setpass)[2:-1])
            quit()
        else:
            print("Password guess ",str(setpass)[2:-1]," does not match, trying next...")
    print("Password not in database, we'll get them next time.")
#MENU SYSTEM FOR GETTING THE HASH OR PASSWORD TO ATTEMPT TO CRACK
def get_hash_or_pw():
    choice = input("Please select 1 to to crack a hash, 2 crack a password.\n>")
    if choice == "1":
        origin = input("Please input the hash to crack.\n>")
        print("Running cracking sequence, please wait:")
        return origin
    if choice == "2":
        setpass = input("Set password to crack.\n>")
        origin = sha1_hash(setpass)
        print("The hash of your password, ", setpass, " is ", origin, ". \nRunning cracking sequence, please wait:")
        return origin
    else:
        get_hash_or_pw()
origin = get_hash_or_pw()
try_worst_passwords(origin)
