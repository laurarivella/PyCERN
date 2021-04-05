# pylint: disable=unused-variable
# pylint: enable=too-many-lines
# pylint is added as global declaration to avoid creating warnings for unused variables

import sqlite3,time,math,random,smtplib,hashlib,sqlite3, re
#Import all the required library, re module provide support for regular expression
from email.message import EmailMessage
#Import from the email.message module. 
regex = "^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"

#Creating connection and to the datbase UserData.db and connection name as db, also
#creating a cursor, this is to perform action inside the database
with sqlite3.connect("UserData.db") as db: 
    cursor = db.cursor()

#Execute a query to creat a table called user, with primary key and few fields, 
#and their datatypes. I'm adding 'NOT NULL' so that field can't be blank, then
#start of the statement with an openbracket and quote marks
cursor.execute("""
CREATE TABLE IF NOT EXISTS user(
userID INTEGER PRIMARY KEY,
username VARCHAR(20) NOT NULL,
firstname VARCHAR(20) NOT NULL,
surname VARCHAR(20) NOT NULL,
email VARCHAR(20) NOT NULL,
password VARCHAR(20) NOT NULL);
""") 
# end of the statement with a close bracket and quote marks

# To create test data use cursor and insert statement, 
# user id will be auto increment so don't need to add here
cursor.execute("""
INSERT INTO user(username,firstname,surname,email,password)
VALUES("test_User","Bob","Smith","shiraj.ali@gmail.com","Bob123")
""")
db.commit() 
# Write to database

# Check the data is entered into the database and print to terminal
cursor.execute("SELECT * FROM user")
#Using the select statement
print(cursor.fetchall()) 
#Print the result on terminal

def otpsend(email): 
#Defined the function for generating OTP and sending email. The function will require an email to run
    OTP=""
    OTP=str(random.randint(10000,99999)) 
    #Select 5 digit random number between 10000 and 99999 to generate OTP
    msg = EmailMessage()
    #Setup the veriable
    msg.set_content('Your OTP Verification is: '+OTP+'. Note.. Please enter One Time Password (OTP) you have 3 attempts') 
    #Embed the OTP in the email message
    msg['Subject'] = 'OTP Verification'
    #Set subject for email
    msg['From'] = 'developer1ali@gmail.com'
    #Set the FROM address for email
    msg['To'] = email
    #Set the TO address for email, replacing 'email' with user input of email
    #msg['To'] = 'shiraj.ali@gmail.com'
    #This Email is hardcoded for testing purpose by removing comment
    s = smtplib.SMTP('smtp.gmail.com', 587) 
    #Setup the sending email server
    s.starttls()
    #Start Transport Layer Security 
    s.login("developer1ali@gmail.com", "My_Password")
    #Credential for the email server, - use a gmail test account usersname and password to send email, 
    # this will be the from address
    s.send_message(msg)
    #Send the composed email message
    return OTP
    # return to variable OTP

def login():
#Create a funcion called login, function need to start with def and end with brackets 
    for i in range(3): 
    #Setup loop, gives user 3 try using for loop
        username = input("Please enter your username: ") 
        #Take user input for username
        email = input("Please enter your email: ")
        #Take user input for email
        password = input("Please enter your password: ") 
        #Take user input for password
        hashedpassword = hashlib.sha256(password.encode()).hexdigest() 
        #For security converting the password as hashed value before storing in to Database
        #use the method encode to encode the password, then used another method hexdigest convert into hex decimal digit.
        with sqlite3.connect("UserData.db") as db: 
        #Using the connection command to connect to the database called UserData as db
            cursor = db.cursor()
        #Create cursor object
        find_user = ("SELECT * FROM user WHERE username = ? AND email = ? AND password = ?") 
        #Using Select statement to find username, email and password. Question mark is used and not using direct veriable name to prevent sql injection
        cursor.execute(find_user,[(username),(email),(hashedpassword)]) 
        #Execute the sql command and replace the question mark with field name in database
        results = cursor.fetchone() 
        #Collect the information from DB and store it under result variable, fetch one record
        #check and loop through the result.
        if results:
            OTP=otpsend(email)
            #Using the function otpsend and match the OTP send on the email
            for y in range(3):
            #Setup a for loop
                #print(OTP)
                #For testing above line can be uncommented to print the emailed OTP on the terminal
                user_otp = input('One Time password is emailed to you. Please check your email (inbox and spam folder) and  \nPlease enter the OTP: ')
                #Taking the user input and storing under variable user_otp
                if user_otp == OTP:
                #Match the stored value in user_otp with OTP send in email
                    break
            if user_otp!=OTP:
            #Check stored otp that don't match the emailed OTP
                print('You have entered incorrect OTP 3 times')
            #After 3 attempt print incorrect message before exiting the system
            else:
                print('Welcome to ASMIS '+results[2]+', you are now logged in') 
                #Print the Welcome message with with first name from database, taken from position 3 in the table
            return
        else:
        # If nothing is found print message and try again
            print("Username and password not recognised")
        again = input("Do you want to try again (y/n): ")
        if again.lower() == "n": 
        #If they answer n for no, then print goodbye and pause for a sec then exit
            print("Goodbye")
            time.sleep(1) 
            #To wait for a bit

def validateOTP(OTP):
#Set validateOTP as function to avoid code duplication
            for y in range(3):
            #Setup loop    
                user_otp = input('One Time password is emailed to you. Please check your email (inbox and spam folder) and  \nPlease enter the OTP: ')
                #Set user_otp as varialbe to take user input to store 
                if user_otp == OTP:
                #Check the OTP if that matched
                    return True
                    #check for true or flase
            if user_otp!=OTP:
            #Check stored value user_otp don't matched with emailed OTP
                print('You have entered incorrect OTP 3 times')
                #Print error message
                return False

def newUser(): 
#Create new function called newUser
    found = 0 
    #Add a flag to make sure username dont exists
    while found ==0: 
    #Loop through the user
        username = input("Please enter a username: ")
        #Take user input for username
        with sqlite3.connect("UserData.db") as db:
        #Using the connection command to connect to the database called UserData as db
            cursor = db.cursor()
            #Create cursor object
        findUser = ("SELECT * FROM user WHERE username = ?") 
        #Checking for the username using variable finduser and select statement
        cursor.execute(findUser,[(username)])
        #Execute the sql command and replace the question mark with field username in database
        if cursor.fetchall(): 
        #If it has data inside it as username is taken, then print message
            print("Username taken, please try again")
            #Print message
        else:
            found = 1
            #When flag matched means a user is found, break out of the loop
    firstName = input("Enter Your first name: ")
    #Take user input for firstname
    surname = input("Enter Your surname: ")
    #Take user input for surname
    email = input("Please enter your email: ")
    #Take user input for email
    password = input("Please enter your password: ")
    #password = "R@m@_f0rtu9e$"
    flag = 0
    while True:   
        if (len(password)<8):
        #setup minimum characters
            flag = -1
            break
        elif not re.search("[a-z]", password): 
        #check for lowercase characters
            flag = -1
            break
        elif not re.search("[A-Z]", password): 
        #check for Upercase characters
            flag = -1
            break
        elif not re.search("[0-9]", password): 
        #check for number
            flag = -1
            break
        elif not re.search("[_@$]", password): 
        #check for special characters
            flag = -1
            break
        elif re.search("\s", password): 
            flag = -1
            break
        else: 
            flag = 0
            print("Valid Password") 
            break
    if flag ==-1: 
        print("password must meet complexity requirements, \nminimum 8 characters, with upercase, lowercase, number and special character")
    password1 = input("Please enter your password: ")
    while password !=password1:
    #Validation, when password entered is not matched
        print("your password didnt match")
        #Print message
        password = input("Please enter your password: ")
        #Take user input for password
        password1 = input("Please enter your password: ")
        #Take user input for password for 2nd time and store in password1
        #for validation
    hashedpassword = hashlib.sha256(password.encode()).hexdigest()
    #Set variable to hash the password. Using the hashlib sha256 to convert password, 
    #use the method encode to encode the password, then used another method hexdigest convert into hex decimal digit.
    #before inserting the data into the database
    try:
    #Use try and ecept method to stop displaying terminal error
        validate = validateOTP(otpsend(email))
        #Calling the function validateOTP with otpsend and store under validate
    except:
    #Using the except method to stop dispaying terminal errors
        print('Error occoured invalid email')
        #Printe the error message
        return
        #go back to the start of function
    if validate:
    #If OTP is validate 
        insertData = '''INSERT INTO user(username,firstname,surname,email,password)
        VALUES(?,?,?,?,?)'''
        cursor.execute(insertData,[(username),(firstName),(surname),(email),(hashedpassword)]) 
        #Execute the command and insert the data
        db.commit() 
        #Write the data into the database
        print('Successfully created the user')
        #Print message
        menu()
        #Run the menu function
    else:
        print('Invalide OTP')
        #Print message 

def passwordreset():
#Create new function called passwordreset
        username = input("Please enter a username: ")
        #Take user input for username
        email = input("Please enter your email: ") 
        #Take user input for email
        password = input("Please enter new password: ")
        password1 = input("Please enter again new password: ")
        while password !=password1: 
        #Validation, when password entered is not matched
            print("your password didnt match")
        #Print message
            password = input("Please enter new password: ")
        #Take user input for password
            password1 = input("Please enter again new password: ")
        #Take user input for password for 2nd time and store in password1 for validation
        hashedpassword1 = hashlib.sha256(password.encode()).hexdigest()
        #For security converting the password as hashed value before storing in to Database
        try:
        #Use try and ecept method to stop displaying terminal error
            validate = validateOTP(otpsend(email))
        #Calling the function validateOTP with otpsend and store under validate
        except:
        #Using the except method to stop dispaying terminal errors
            print('Error occoured invalid email')
        #Printe the error message
            return
        #go back to the start of function
        if validate:
        #If OTP is validate        
            with sqlite3.connect("UserData.db") as db:
        #Using the connection command to connect to the database called UserData as db
                cursor = db.cursor()
                #Create cursor object
                findUser = ("SELECT * FROM user WHERE username = ? AND email = ?") 
                #Checking for the username using variable finduser and select statement
                cursor.execute(findUser,[(username),(email)])
                #Execute the command to find the correct user
                updateData = '''UPDATE user SET password = ? WHERE username = ? '''
                cursor.execute(updateData,[(hashedpassword1),(username)])
                #Execute the command and update the data
                db.commit()
                #Write the data into the database
                print('Successfully updated the password')
                #Print message
                menu()
                #Run the menu function
        else:
            print('Invalide OTP')
            #Print message 
            menu()

def menu(): 
#Create a funcion called menu
    while True: 
    #Create a loop for the menu
        print("Welcome - Please select an option: ") 
        #Print a welcome message
        menu =('''
        1 - Create New user
        2 - Login to system
        3 - Reset Password
        4 - Exit\n''')

        userChoice = input(menu)
        #Take user choice for the menu
        if userChoice == "1": 
            #Take user input
            newUser() 
            #Run the new user function

        elif userChoice == "2":
            #Take user input
            login() 
            #Run the login function

        elif userChoice == "3":
            #Take user input
            passwordreset() 
            #Run the login function

        elif userChoice == "4":
            #Take user input
            print("GoodBye")
            break
            #Print GoodBye and exit the system
        else:
            print("Command not recognised: ")
            #Print when a valid menu option not selected
        break #break out
menu()
#Run the menu function