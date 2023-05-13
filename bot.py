from firebase_admin import auth, credentials, firestore,initialize_app
from google.cloud.firestore_v1 import ArrayUnion
from google.cloud import firestore as fs
from flask import Flask, render_template, request, jsonify,redirect,url_for,session
from google.oauth2 import service_account
from google.cloud import storage
account_credentials = service_account.Credentials.from_service_account_file('service.json')
client = storage.Client(credentials=account_credentials)
bucket = client.get_bucket('my_bucket125')
app = Flask(__name__,static_url_path='/static')
import bcrypt
import os
import datetime
cred = credentials.Certificate("firebase_adminsdk.json")
initialize_app(cred)
db = firestore.client()
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = "super"
@app.route('/delete_directory',methods=['POST'])
def delete_directory():
    data = request.json
    collection_ref = db.collection("directory")
    doc_ref = collection_ref.document(data.get('delName'))
    doc_snapshot = doc_ref.get()
    no_of_documents = len(doc_snapshot.get('documents'))
    if no_of_documents ==0:
        doc_ref.delete()
        return jsonify('true')
    else:
        return jsonify('false')


@app.route('/create_directory',methods=['POST'])
def create_directory():
    data = request.json
    collection_ref = db.collection("directory")
    json_str = {'dir_name':data.get('dirName'),'documents':[],'user_id':session['user_id'],'storage':0}
    doc_ref = collection_ref.document(data.get('dirName'))
    doc_ref.set(json_str)

    return redirect(url_for('home'))
@app.route('/home/<user>')
def home(user):
    if session['user_id']:
        my_collection = db.collection('directory')
        user_id = session.get('user_id')

        query = my_collection.where('user_id','==',user_id)
        docs = query.get()
        data = []
        for doc in docs:
            data.append(doc.to_dict()['dir_name'])

        return render_template("home.html",directories = data)
    else:
        return "Page not found"

@app.route('/directory_view/<dirName>',methods=['GET','POST'])
def directory_view(dirName):
    dir_ref = db.collection("directory")
    dir_doc = dir_ref.where("dir_name", "==", dirName).where("user_id","==",session['user_id']).get()
    data = []
    for doc in dir_doc:
        data.append(doc.to_dict()['dir_name'])
        data.append(doc.to_dict()['storage'])
        data.append(doc.to_dict()['documents'])
        print(data)
    if request.method=='POST' and request.form['form_id'] == 'submit_file':
        file = request.files['file']
        filename = os.path.basename(file.filename)
        file_length = len(file.read())
        file_size = file_length / (1000000)
        blob = bucket.blob(file.filename+"_"+str(datetime.datetime.now()))
        file.seek(0)
        blob.upload_from_file(file)
        url = blob.public_url
        doc_ref = db.collection('documents').document(filename+str(datetime.datetime.now()))
        doc_ref.set({
            'file_name': filename,
            'upload_date': datetime.datetime.now(),
            'dir_name':dirName,
            'user_id':session['user_id'],
            'file_size':file_size,
            'url':url
        })

        if data[1]+file_size < 5:
            (dir_doc[0].reference).update({
                'documents': ArrayUnion([filename]),
                'storage': fs.Increment(file_size)
            })

    files = []

    for document in data[2]:
        documents = db.collection("documents")
        dir_document = documents.where("file_name","==",document).where("user_id","==",session['user_id']).get()
        latest_doc = None
        for doc in dir_document:
            doc_dict = doc.to_dict()
            if latest_doc is None or doc_dict['upload_date'] > latest_doc['upload_date']:
                latest_doc = doc_dict
        files.append([latest_doc['file_name'],latest_doc['upload_date']])

    if request.method=='POST' and request.form['form_id']=="delete_file":
        file_name = request.form['file_name']
        document_collection = db.collection("documents")
        documents = document_collection.where("dir_name","==",dirName).where("file_name","==",file_name).where("user_id","==",session['user_id']).get()
        for doc in documents:
            document_collection.document(doc.to_dict()['file_name']+str(doc.to_dict()['upload_date']))
        file_size = documents[0].to_dict()['file_size']
        print(file_size)
        directory_ref = dir_ref.document(dirName)
        directory_ref.update({
                'documents': fs.ArrayRemove([file_name]),
                'storage': fs.Increment(-file_size)
            })

    return render_template("directory_view.html",heading=dirName,files = files,link = '/directory_view/'+dirName)

@app.route('/signup', methods=['GET','POST'])
def signup():
    # Get user data from request body
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['username']
        salt = bcrypt.gensalt()  # Generate a salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        try:
            # Create new user account with Firebase Authentication
            user = auth.create_user(email=email, password=password)

            # Store user information in Firestore
            user_ref = db.collection('users').document(name)
            user_ref.set({
                'email': email,
                'name': name,
                'password':hashed_password,
                'user_id':user.uid
            })

            return redirect(url_for('login'))

        except Exception as e:
            return render_template('sign_up.html',err=str(e))
    return render_template('sign_up.html')
@app.route('/', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']
        user_ref = db.collection("users")
        user_docs = user_ref.where('email','==',email).get()
        for doc in user_docs:
            if bcrypt.checkpw(password.encode('utf-8'), doc.to_dict()['password']):

                session['user_id'] = doc.to_dict()['user_id']
                return redirect(url_for('home',user=doc.to_dict()['name']))
            else:
                err = "Invalid ID or Password"
                return render_template('login.html',error=err)
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear session
    session.clear()
    # Redirect to login page
    return "success"

@app.route('/admin',methods=['GET','POST'])
def admin():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        admin_collection = db.collection("admins")
        admin_docs = admin_collection.get()
        for doc in admin_docs:
            if username == doc.to_dict()['username'] and password == doc.to_dict()['password']:
                session['admin_id'] = username
                return redirect(url_for('dashboard'))
            else:
                return render_template('admin.html',message="Invalid username or password")
    return render_template('admin.html')

@app.route('/dashboard')
def dashboard():
    if session['admin_id']:
        # retrieve all users from Firestore
        users_ref = db.collection('users')
        users = [doc.to_dict() for doc in users_ref.stream()]

        # retrieve directories for each user
        for user in users:
            dir_ref = db.collection('directory').where('user_id', '==', user['user_id'])
            directories = [doc.to_dict() for doc in dir_ref.stream()]
            user['directories'] = directories
            # # retrieve documents for each directory
            # for directory in directories:
            #     doc_ref = db.collection('documents').where('file_name', 'in', directory['documents']).stream()
            #     documents = [doc.to_dict() for doc in doc_ref]
            #     directory['documents'] = documents

        return render_template('users.html', users=users)
    else:
        return "Page not found"

@app.route('/versions')
def versions():
    file_name = request.args.get('name')
    file_collection = db.collection("documents")
    files = file_collection.where("file_name","==",file_name).where("user_id","==",session["user_id"]).get()
    files_list = []
    for file in files:
        files_list.append(file.to_dict())
    print(files_list)
    return render_template('versions.html',documents = files_list)

@app.route('/shared',methods=['POST'])
def shared():
    shared_collection = db.collection("shared")
    user_collection = db.collection("users")
    user_docs = user_collection.where("user_id","==",session['user_id']).get()
    user_name = user_docs[0].to_dict()['name']
    shared_docs = shared_collection.where("receiver","==",user_name).get()
    docs_list = []
    for docs in shared_docs:
        docs_list.append([docs.to_dict()['receiver'],docs.to_dict()['url']])
    return render_template('shared.html',documents=docs_list)

@app.route('/share_doc',methods=['POST'])
def share_doc():
    data = request.get_json()
    document_name = data["document_name"]
    sender_name = data["receiver_name"]
    users_collection = db.collection("users").where("name","==",sender_name).get()
    user_id = users_collection[0].to_dict()['user_id']
    shared_docs = db.collection("documents").where("user_id","==",user_id).where("file_name","==",document_name).get()
    share_collection = db.collection("shared").document()
    share_collection.set({
        'receiver':users_collection[0].to_dict()['name'],
        'url':shared_docs[0].to_dict()['url']
    })
    return redirect(url_for('home'))
app.debug = True
app.run()
