from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
import re, md5

app = Flask(__name__)
app.secret_key = '123456'
mysql = MySQLConnector(app, 'mydb')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
	if session.get('name') is None:
		session['name'] = ''
	if session.get('isdigit') is None:
		session['id'] = 0
	return render_template('index.html')

@app.route('/validate', methods=['POST'])
def validate():
	email = request.form['email']
	pwd = request.form['pwd']

	if request.form['action'] == 'login':
		query = "SELECT * FROM users WHERE email='{}'".format(email)   
		user = mysql.query_db(query)
		if len(user) != 0:
 			encrypted_password = md5.new(pwd).hexdigest()
 			if user[0]['password'] == encrypted_password:
 				session['name'] = user[0]['first_name']
 				session['id'] = user[0]['id']
 				return redirect('/wall')
 			else:
 				flash('Password is not valid', 'danger')
		else:
			flash('Email is not valid', 'danger')
	else:
		first_name = request.form['first_name']
		last_name = request.form['last_name']
		confirmPwd = request.form['confirmPwd']
		flag = True
		if len(first_name) < 1:
			flag = False
			flash('First Name should be more than one character', 'danger')
		elif any(char.isdigit() for char in first_name) == True:
			flag = False
			flash('First Name should have only characters', 'danger')
		if len(last_name) < 1:
			flag = False
			flash('Last Name should be more than one character', 'danger')
		elif any(char.isdigit() for char in last_name) == True:
			flag = False
			flash('Last Name should have only characters', 'danger')
		if len(email) < 1:
			flag = False
			flash('Email should not be blank', 'danger')
		elif not EMAIL_REGEX.match(email): 
			flag = False
			flash('Email is not valid!', 'danger')
		if len(pwd) < 8:
			flag = False
			flash('Password should be at least 8 characters', 'danger')
		if len(confirmPwd) < 8 or pwd!=confirmPwd:
			flag = False
			flash('Password and Confirm Password should match', 'danger')
		if flag:
			hashed_pwd = md5.new(pwd).hexdigest()
			query = "insert into users (first_name, last_name, email, password, created_at, updated_at) values('{}', '{}', '{}', '{}', NOW(), NOW())".format(first_name, last_name, email, hashed_pwd)
			mysql.query_db(query)
			flash('You are successfully registered. Enter credentials to login', 'success')
			return redirect('/')
	return redirect('/')

@app.route('/wall')
def wall():
	post_query = "SELECT users.first_name, users.last_name, messages.message, messages.id, messages.user_id, messages.created_at FROM messages JOIN users ON messages.user_id=users.id order by created_at desc"
	comment_query = "SELECT comments.comment, comments.message_id, comments.created_at, users.first_name, users.last_name FROM comments INNER JOIN users ON users.id=comments.user_id INNER JOIN messages ON messages.id = comments.message_id order by comments.created_at"
	messages = mysql.query_db(post_query)
	comments = mysql.query_db(comment_query)
	return render_template("wall.html", messages=messages, comments=comments)

@app.route('/add_message', methods=['POST'])
def add_message():
	msg = request.form['message']
	query = "insert into messages(message, created_at, updated_at, user_id) values('{}', NOW(), NOW(), {})".format(msg, session['id'])
	mysql.query_db(query)
	return redirect('/wall')

@app.route('/add_comment/<id>', methods=['POST'])
def add_comment(id):
	msg = request.form['comment']
	query = "insert into comments(comment, created_at, updated_at, message_id, user_id) values('{}', NOW(), NOW(), {}, {})".format(msg, id, session['id'])
	mysql.query_db(query)
	return redirect('/wall')

@app.route('/delete/<msg_id>', methods=['POST'])
def delete(msg_id):
	query = "select created_at as created_at from messages where id={}".format(msg_id)
	res = mysql.query_db(query)
	check_time = "select TIMEDIFF(NOW(), '{}') / 60 as timeDiff".format(res[0]['created_at'])
	result = mysql.query_db(check_time)
	print "%%%%%%%%%%%%%%%%%%%%     {}".format(result[0]['timeDiff'])
	flag = result[0]['timeDiff'] < 30
	print "))))))))))))))))))))))))))))  {}".format(flag)
	if result[0]['timeDiff'] < 30 :
		print "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
		query_comments = "delete from comments where message_id={}".format(msg_id)
		query = "delete from messages where id={}".format(msg_id)
		mysql.query_db(query_comments)
		mysql.query_db(query)
	else:
		flash('Sorry, message posted more than 30 mins ago cannot be deleted', 'info')
	return redirect('/wall')

@app.route('/logout', methods=['POST'])
def logout():
	session.clear()
	return redirect('/')

app.run(debug=True)