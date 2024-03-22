from flask_app import app
from flask import render_template, redirect, request, session, flash, get_flashed_messages
from flask_app.models.login_register import User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register/user', methods=['POST'])
def register_user():
    if not User.validate_user(request.form):
        flash('This needs to be fixed!!!!', 'register/user')
        return redirect('/')
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': bcrypt.generate_password_hash(request.form['password'])
    }
    id = User.save(data)
    session['user_id'] = id
    return redirect('/main/page')

@app.route('/login/user', methods=['POST'])
def login_user():
    one_user = User.get_by_email(request.form)
    if not one_user:
        flash('Invalid Email', 'login/user')
        return redirect('/')
    if not bcrypt.check_password_hash(one_user.password, request.form['password']):
        flash('Invalid Password', 'login/user')
        return redirect('/')
    session['user_id'] = one_user.id
    return redirect('/main/page')

@app.route('/main/page')
def main_page():
    if 'user_id' not in session:
        flash('You need to log in first silly goose!', 'login/user')
        return redirect('/logout')
    data = {
        'id': session['user_id']
    }
    one_user = User.get_by_id(data)
    flash_messages = get_flashed_messages(with_categories=True)
    return render_template('success.html', user=one_user, messages=flash_messages)

@app.route('/success')
def success():
    if 'user_id' not in session:
        flash('Please log in first!', 'login/user')
        return redirect('/')
    data = {
        'id': session['user_id']
    }
    one_user = User.get_by_id(data)
    return render_template('success.html', user=one_user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')



