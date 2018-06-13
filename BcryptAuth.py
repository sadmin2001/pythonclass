import bcrypt, csv
#BCRYPT AUTHENTICATION SYSTEM IN 69 LINES, REAL FINE!
#Select login options and either register or log in to the system
def LoginSelect():
    select = input("WELCOME TO THE SYSTEM, PLEASE SELECT AN OPTION\nSELECT OPTION 1 TO REGISTER, 2 TO LOG IN\n>")
    if select == "1":
        RegisterUser()
    if select == "2":
        LoginUser()
    else:
        print("Invalid option, please try again")
        LoginSelect()
#Register the user and hash the password, printing the results to the creds.csv file
def RegisterUser():
    username = input("Please input your username\n>")
    ExistingUsername(username)
    password = input("Please create your password\n>")
    check = input("Please confirm your password\n>")
    MatchingPassword(password, check)
    # Hash a password for the first time, with a randomly-generated salt
    password = bytes(password, encoding='utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    # Turn the credentials into a key-value pair in a dictionary and write to creds.csv to register account
    CredsEntry = {username: hashed}
    with open('creds.csv', 'a') as csvfile:
        filewriter = csv.writer(csvfile)
        for key, value in CredsEntry.items():
            filewriter.writerow([key, value])
            print("You have registered your login. You may now log in.")
            csvfile.close()
            LoginSelect()
#Logs in the user, checking creds.csv for the user name and then matching the attempt to the hashed password
def LoginUser():
    loginattempt = input("Please enter your login.\n>")
    passwordattempt = input("Please enter your password.\n>")
    passwordattempt = bytes(passwordattempt, encoding='utf-8')
    check = "okay"
    with open('creds.csv', 'r') as csvfile:
        my_content = csv.reader(csvfile, delimiter=',')
        for row in my_content:
            if loginattempt == row[0]:
                print("Username exists!")
                check = row[1]
                check = bytes(check, encoding='utf-8')[2:-1]
                if bcrypt.checkpw(passwordattempt, check):
                    print("The password matches, you are logged in!")
                    quit()
                else:
                    print("Invalid username/password combination, please try again another day friend")
#Checks to see if the user already exists in the creds.csv file
def ExistingUsername(username):
    with open('creds.csv', 'r') as csvfile:
        my_content = csv.reader(csvfile, delimiter=',')
        for row in my_content:
            if username == row[0]:
                print("Username exists! Please select another")
                username = input(">")
                ExistingUsername(username)
#Checks to see that the passwords match eachother for registration
def MatchingPassword(password, check):
    if password == check:
        pass
    else:
        password = input("Passwords did not match, please enter again\n>")
        password = bytes(password, encoding='utf-8')
        check = input("Please confirm your password\n>")
        check = bytes(check, encoding='utf-8')
        MatchingPassword(password, check)
LoginSelect()
