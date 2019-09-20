from bottle import route, run, response, redirect, request, template, static_file
import bcrypt
import re
import sqlite3

db = sqlite3.connect('main.db')
cursor = db.cursor()


@route('/')
@route('/dashboard')
def dashboard():
    if not request.get_cookie('user_id', secret='user_id'):
        return redirect('/login')
    user_id = request.get_cookie('user_id', secret='user_id')
    transact = cursor.execute(
        'SELECT fullname FROM user WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    return template('templates/dashboard.html', name=result[0])


@route('/logout')
def logout():
    if not request.get_cookie('user_id', secret='user_id'):
        return redirect('/login')
    response.delete_cookie('user_id', secret="user_id")
    return redirect('/')


@route('/login')
def login():
    if request.get_cookie('user_id', secret='user_id'):
        return redirect('/')
    return template('templates/login.html')


@route('/login', method='POST')
def handle_login():
    email = request.forms.get('email')
    password = request.forms.get('password')

    if email != "" or password != "":
        transact = cursor.execute(
            'SELECT id, fullname, password FROM user WHERE email = ?', (email,))
        result = cursor.fetchone()
        if result != None:
            passwd = bcrypt.checkpw(password.encode('utf-8'), result[2])
            if passwd:
                response.set_cookie('user_id', result[0], secret='user_id')
                return {'success': True, 'message': 'Logged in successfully ...'}
            else:
                return {'success': False, 'message': 'Invalid password'}
        else:
            return {'success': False, 'message': 'Invalid Email'}
    else:
        return {'success': False, 'message': 'Email or Password Field cannot be empty'}


@route('/signup')
def signup():
    if request.get_cookie('user_id', secret='user_id'):
        return redirect('/')
    try:
        cursor.execute('''
            CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT, fullname TEXT, email TEXT UNIQUE, password TEXT)
        ''')
        print('Table Created')
    except:
        print('cannot create table')
    return template('templates/register.html')


@route('/signup', method='POST')
def handle_signup():

    fullname = request.forms.get('fullname')
    email = request.forms.get('email')
    password = request.forms.get('password')
    cpassword = request.forms.get('cpassword')

    # Serverside validation
    if (fullname == ""):
        return {'success': False, 'message': 'Name field cannot be empty'}
    elif len(fullname) < 8:
        return {'success': False, 'message': 'Name too short, must be upto six characters'}
    elif (email == ""):
        return {'success': False, 'message': 'Email field eannot be empty'}
    elif (re.match(r'\w+\.?@\w+\.\w+', email) == None):
        return {'success': False, 'message': 'Please Enter a valid email address'}
    elif password == "" or cpassword == "" or len(password) < 6 or len(cpassword) < 6:
        return {'success': False, 'message': 'Passwords too short, must be upto six characters'}
    elif password != cpassword:
        return {'success': False, 'message': 'Passwords do not match'}
    else:
        '''check if email already exist in the database'''
        transact = cursor.execute(
            'SELECT * FROM user WHERE email = ?', (email,))
        result = cursor.fetchone()
        if result:
            return {'success': False, 'message': 'Email already exist'}

        '''Or proceed to create an account'''
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
        try:
            cursor.execute('INSERT INTO user (fullname, email, password) VALUES(?,?,?)',
                           (fullname, email, hashed_pw,))
            db.commit()
            print('document inserted')
            return {'success': True, 'message': 'Successfully registered, redirecting to login ...'}
        except:
            db.rollback()
            print('Unkbown error in registration')
            return {'success': False, 'message': 'Unknown error during registration'}


# Return static files
@route('/assets/<filepath:path>')
def static(filepath):
    return static_file(filepath, root='./assets/')


run(reloader=True, debug=True)
