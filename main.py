from flask import Flask, render_template
from flask_mail import Mail,Message
import os
import hashlib
# from app import app
# from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pickle
import os.path
import base64
import email
from bs4 import BeautifulSoup
import imaplib
from email.header import decode_header
from flask import Flask, redirect, url_for, request
from datetime import date,timedelta
app = Flask(__name__) 
# Define the SCOPES. If modifying it, delete the token.pickle file.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

#login/signup

from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt

app = Flask(__name__)
app.secret_key = "testing"
client = pymongo.MongoClient("#")
db = client.get_database('#')
records = db.register

@app.route("/", methods=['post', 'get'])
def index():
    message = '' 
    
    if "email" in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        check="False"
        Firstname = request.form.get("Firstname")
        Lastname = request.form.get("Lastname")
        email = request.form.get("email")
        vall="@gmail"
        if vall not in email:
            print("valid email address")
           
            return render_template('index.html', checks=check)

        Teamname = request.form.get("Teamname")
        Role = request.form.get("user_role")
        
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        gmailpassword=request.form.get("gmailpass")
        user_data = records.find_one({"name": Firstname})
        user_data = records.find_one({"name": Lastname})
        # user_data = records.find_one({"name": Teamname})
        # user_data = records.find_one({"name": Role})
        email_found = records.find_one({"email": email})
        if user_data:
            message = 'There already is a user by that name'
            return render_template('index.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('index.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'Firstname': Firstname,'Lastname': Lastname,'Teamname': Teamname,'Role':Role, 'email': email, 'password': hashed,'Gmailpass':gmailpassword}
            records.insert_one(user_input)
            
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            return redirect(url_for("login"))
    return render_template('index.html')


# add member

@app.route('/logged_in', methods=['post', 'get'])
def logged_in():
    if "gmail" in session["email"]:
        email = session["email"]
    
        client = pymongo.MongoClient("mongodb://localhost:27017/todo_db")
        db = client.get_database('total_records')
        records = db.register
        data = db.register.find({"email":email})
        user_data = db.register.find({"email":email})
        for j in user_data:
            user=j['Firstname']
        print(user)
        try:
            data = db.register.find()
            print(data,"dsfffffffffff")

            return render_template('logged_in.html', datas = data, username = user)
        except Exception as e:
            return dumps({'error' : str(e)})
   
    return render_template('logged_in.html', email=email)
    

    return render_template('logged_in.html',role)

@app.route('/popup', methods=['post', 'get'])
def popup():
    if "email" in session:
        email = session["email"]
        return render_template('popup.html', email=email)


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in  session:
        return redirect(url_for('logged_in'))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password") 
        print(password)   
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                

                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("signout.html")
    else:
        return render_template('index.html')
@app.route("/email_sync",methods=["POST", "GET"])
def ReadEmail():
    import imaplib
    import email
    from email.header import decode_header
    import webbrowser
    import os
    if "gmail" in session["email"]:
        username = session["email"]
    client = pymongo.MongoClient("#")
    db = client.get_database('total_records')
    mycols=db["emailData"]
    records = db.register
    data = db.register.find({"email":username})
    
    # account credentials
    for i in data:
        password=i["Gmailpass"]
        team=i["Teamname"]
    
    data= db.register.find({"email": username})
    for i in data:
        team=i['Teamname']
    # checking email of team members
    check =  db.register.find({"Teamname":team})
    checkemails=[]
    for x in check:
        data=x['email']
        checkemails.append(data)
    # checking messageg of team members
    msglst=[]
    msg = db.emailData.find()
    for msgdata in msg:
        msgd=msgdata['message']
        msglst.append(msgd)
    def clean(text):
    #     clean text for creating a folder
        return "".join(c if c.isalnum() else "_" for c in text)
    # create an IMAP4 class with SSL 
    imap = imaplib.IMAP4_SSL("imap.gmail.com")
# authenticate
    imap.login(username, password)
    imap.select("INBOX")
    status, messages = imap.select("INBOX")
    # number of top emails to fetch
    N = 100000000000
    # total number of emails
    messages = int(messages[0])
    print(messages)

    # calculating 90 days from current date
    currentdate = date.today()
    daata= currentdate-timedelta(90)
    # delta = currentdate - daata       # as timedelta
    d=str(daata.strftime(" %d-%b-%Y"))

    # fetching emails of 90 days

    typ, data = imap.search(None,'(SINCE "{}")'.format(d.strip())) 
    msglist=[]
    s=data[0].split()
    for i in range(len(s)):
        p=s[i].decode('utf8')
        msglist.append(p)
    print(msglist)

    for i in msglist:
    # fetch the email message by ID\
#     try:
        res, msg = imap.fetch(str(i), "(RFC822)")
        for response in msg:
            if isinstance(response, tuple):
                # parse a bytes email into a message object
                msg = email.message_from_bytes(response[1])

                # decode the email subject
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    # if it's a bytes, decode to str
                    subject = subject.decode(encoding="utf-8")
                Date, encoding = decode_header(msg["Date"])[0]
                if isinstance(Date, bytes):
                    # if it's a bytes, decode to str
                    Date = Date.decode(encoding="utf-8")
                # decode email sender
                From, encoding = decode_header(msg.get("From"))[0]
                if isinstance(From, bytes):
                    From = From.decode(encoding)
    #               
                if len(From.split())==2:
                    Firstname=From.split()[0]
                    print("Firstname:))))))))))", Firstname)
                if len(From.split())==2:
                    From=From.split()[1].replace('<',' ').replace('>',' ')
                    print("From:))))))))))", From)
                if len(From.split())==3:
                    Firstname=From.split()[0]
                    print("Firstname:))))))))))", Firstname)
                    Lastname=From.split()[1]
                    print("Lastname:))))))))))", Lastname)
                    From=From.split()[2].replace('<',' ').replace('>',' ')
                    print("From:))))))))))", From)
                if len(From.split())==4:
                    Firstname=From.split()[0]
                    print("Firstname:))))))))))", Firstname)
                    Lastname=From.split()[1]
                    print("Lastname:))))))))))", Lastname)
                    Lastname=From.split()[2]
                    print("Lastname:))))))))))", Lastname)
                    From=From.split()[3].replace('<',' ').replace('>',' ')
                    print("From:))))))))))", From)


                Subject=subject
                print("Subject:$$$$$$$$$$$$$$$$$", subject)              
                Date=Date
                print("date:###################",Date)

                # if the email message is multipart
                if msg.is_multipart():

                    # iterate over email parts
                    for part in msg.walk():
                        # extract content type of email
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        try:
                            # get the email body
                            body = part.get_payload(decode=True).decode()
                        except:
                            pass

                        if content_type == "text/plain" and "attachment" in content_disposition :
                            # print text/plain emails and skip attachments
                            Message=body
                            print(Message,"---------------------fgdfgdf--------------------------------------")
                            filename = part.get_filename()
                            if filename:
                                fname=filename
                                filepath = os.path.join("media", filename)

                                # download attachment and save it
                                print("filepathfilepathfilepathfilepathfilepathfilepath",filepath)
                                open(filepath, "wb").write(part.get_payload(decode=True))
                                fname=filepath

                                sha256_hash = hashlib.sha256()
                                with open(fname,"rb") as f:
                                    # Read and update hash string value in blocks of 4K
                                    for byte_block in iter(lambda: f.read(4096),b""):
                                        sha256_hash.update(byte_block)
                                        hash_file=sha256_hash.hexdigest()
                            msgdate= db.emailData.find({"date":Date})
                            for d in msgdate:
                                mdate=d["date"]
                            if date!=mdate:
                                if Message not in msglst:
                                    if From.strip() in checkemails:
                                        mydict = {"firstname": Firstname, "lastname": Lastname,"teamname": team ,"From":From,"Reciever":username,"subject": subject,"message": body,"date":Date,"file":{"filename":filename,"hash_file":hash_file}}
                                        x = mycols.insert_one(mydict)

                        elif "attachment" in content_disposition:
                                filename = part.get_filename()

                                Message=body
                                filelst=[]
                                tyfile=type(filename)
                                if tyfile =="Array":
                                    filelst.append(filename)
                                
                                print("filelstfilelstfilelstfilelstfilelstfilelst",filelst)
                                if From.strip() in checkemails:
                                   
                                    if filename:
                                        fname=filename
                                        filepath = os.path.join("media", filename)

                                        # download attachment and save it
                                        print("filepathfilepathfilepathfilepathfilepathfilepath",filepath)
                                        open(filepath, "wb").write(part.get_payload(decode=True))
                                        fname=filepath

                                        sha256_hash = hashlib.sha256()
                                        with open(fname,"rb") as f:
                                            # Read and update hash string value in blocks of 4K
                                            for byte_block in iter(lambda: f.read(4096),b""):
                                                sha256_hash.update(byte_block)
                                                hash_file=sha256_hash.hexdigest()
                                        print("hash_filehash_filehash_filehash_filehash_filehash_file",hash_file)
                                            
                                        mydict = {"firstname": Firstname, "lastname": Lastname,"teamname": team ,"From":From,"Reciever":username,"subject": subject,"message": Message,"date":Date,"file":{"filename":filename,"hash_file":hash_file}}
                                        x = mycols.insert_one(mydict)
                                        print("data inserted with  attachment sucessfullly.....................................")
                                else:
                                    if From.strip() in checkemails:
                                        if filename:
                                            fname=filename
                                            filepath = os.path.join("media", filename)
                                            # download attachment and save it
                                            print("filepathfilepathfilepathfilepathfilepathfilepath",filepath)   
                                            open(filepath, "wb").write(part.get_payload(decode=True))
                                            fname=filepath
                                            print("fnamefnamefnamefnamefnamefnamefname",fname)
                                            sha256_hash = hashlib.sha256()
                                            with open(fname,"rb") as f:
                                                # Read and update hash string value in blocks of 4K
                                                for byte_block in iter(lambda: f.read(4096),b""):
                                                    sha256_hash.update(byte_block)
                                                    hash_file=sha256_hash.hexdigest()
                                            print("emailmatched.......")
                                            mydict = {"firstname": Firstname, "lastname": Lastname,"teamname": team ,"From":From,"Reciever":username,"subject": subject,"message": body,"date":Date,"file":{"filename":fname,"hash_file":hash_file}}
                                            x = mycols.insert_one(mydict)
                                            print("data inserted sucessfullly.....................................")
                        


                else:
                    # extract content type of email
                    content_type = msg.get_content_type()

    # close the connection and logout
    imap.close()
    imap.logout()

    detail=mycols.find({'Reciever':username})
    return render_template('email-sync.html',details=detail)


#end of code to run it
if __name__ == "__main__":
  app.run(debug=True)

  