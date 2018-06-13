# Python Brute Forcer - SHA1

This project is to demonstrate brute-forcing with Python. It has two options.

Brute force password - It will take a password, convert it into a sha1 hash, and then compare that hash to 10,000 hashes of the worst known passwords.

Brute force hash - It will take a SHA1 hash, and compare it to SHA1 hashes of the top 10,000 worst known user passwords. 


Installation: 
Run "sudo pip3 install -r requirements.txt"
Run "python3 hash.py"

If you get an error that reads:
urllib.error.URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:777)>

In your terminal, run "/Applications/Python\ 3.6/Install\ Certificates.command"
This will update your certificates

