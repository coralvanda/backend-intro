#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import codecs
import re
import hashlib
import hmac
import Cookie
import datetime
import random
import string
from flask import url_for

from google.appengine.ext import db

SECRET = 'secret_cookie_string'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)


class Handler(webapp2.RequestHandler):
	"""Allows for easier writing and rendering of pages"""
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class FoodHandler(Handler):
	"""Accepts items to add to a shopping list, and displays it"""
	def get(self):
		items = self.request.get_all("food")
		self.render("shopping_list.html", items = items)


class FizzBuzzHandler(Handler):
	"""Takes a number from the URL to perform fizzbuzz up to 
	that number and display the result"""
	def get(self):
		n = self.request.get('n', 0)
		n = n and int(n)
		self.render('fizzbuzz.html', n=n)


class Rot13Handler(Handler):
	"""Accepts text to perform a rot13 encoding/decoding on
	it, and then displays the result"""
	def get(self):
		text = self.request.get("text")
		self.render('rot13.html', text=text)

	def post(self):
		text = self.request.get("text")
		encoder = codecs.getencoder("rot-13")
		encoded_text = encoder(text)[0]
		self.render('rot13.html', text=encoded_text)


class Art(db.Model):
	"""Creates an entity for holding pieces of submitted ascii art"""
	title 	= db.StringProperty(required=True)
	art 	= db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)


class Ascii(Handler):
	"""Allows a person to submit new ascii art, and displays up to 10
	of the most recently submitted ascii art pieces"""
	def render_ascii(self, title="", art="", error=""):
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
		self.render("ascii.html", 
        	title=title, 
        	art=art, 
        	error=error,
        	arts=arts)

	def get(self):
		self.render_ascii()

	def post(self):
		title = self.request.get('title')
		art = self.request.get('art')

		if title and art:
			a = Art(title=title, art=art)
			a.put()
			self.redirect("/ascii")
		else:
			error = "we need both a title and some artwork!"
			self.render_ascii(title, art, error)


def valid_username(username):
	# Confirms that a given username conforms to my requirements
	user_re = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
	return user_re.match(username)

def valid_password(password):
	# Confirms that a given password conforms to my requirements
	pw_re = re.compile(r"^.{3,20}$")
	return pw_re.match(password)

def valid_email(email):
	# Confirms that a given email is probably valid
	email_re = re.compile(r'^[\S]+@[\S]+.[\S]+$')
	return email_re.match(email)

def hash_str(s):
	# Returns an hmac-hashed version of the input string
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	# Returns the given string and its hashed version as a single string
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	# Confirms that a given string/hash pair is valid
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_salt(length=5):
	# Creates/returns a string of random letters, 5 by default
	return "".join(random.choice(string.letters) for x in range(length))

def make_pw_hash(name, pw, salt=None):
	# Uses salt to make a more secure password hash
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	# Verifies that a password is valid using the hash
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	# Returns the user's database key
	return db.Key.from_path('users', group)

def check_login(cookie):
	if not cookie:
		return False
	else:
		return check_secure_val(cookie)


class User(db.Model):
	"""Creates an entity for storing users and provides
	functionality for finding and handling users"""
	name = db.StringProperty(required=True)
	pw_hash = db.StringProperty(required=True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = user_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent=users_key(),
			name=name,
			pw_hash=pw_hash,
			email=email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


class SignupHandler(Handler):
	"""Allows a user to signup, enforcing rules for username, password
	and allowing an optional email input (also checked for validity).
	Then sets a cookie and sends the user to the welcome page"""
	def get(self):
		self.render('signup.html')

	def post(self):
		user_name	= self.request.get('username')
		password 	= self.request.get('password')
		verify 		= self.request.get('verify')
		email 		= self.request.get('email')

		username_error 	= ''
		password_error 	= ''
		verify_error	= ''
		email_error		= ''
		valid_form = True

		u = User.by_name(user_name)
		if u:
			username_error = "That user already exists."
			valid_form = False
		if not valid_username(user_name):
			username_error = "Please enter a valid user name"
			valid_form = False
		if not valid_password(password):
			password_error = "Please enter a valid password"
			valid_form = False
		if not password == verify:
			verify_error = "Password does not match"
			valid_form = False
		if email and not valid_email(email):
			email_error = "Please enter a valid email"
			valid_form = False

		if valid_form:
			u = User.register(user_name, password, email)
			u.put()
			cookie_val = make_secure_val(user_name)
			self.response.set_cookie('name', cookie_val)
			self.redirect('/welcome')
		else:
			self.render('signup.html',
				username=user_name,
				email=email, 
				username_error=username_error,
				password_error=password_error,
				verify_error=verify_error,
				email_error=email_error)


class LoginHandler(Handler):
	"""Allows users to log in, enforcing rules for username and password.
	If valid, sets a cookie and redirects to the welcome page."""
	def get(self):
		self.render('login.html')

	def post(self):
		user_name	= self.request.get('username')
		password 	= self.request.get('password')
		username_error 	= ''
		password_error 	= ''
		valid_form = True

		u = User.login(user_name, password)
		if not u:
			username_error = "Invalid login"
			valid_form = False
		if not valid_username(user_name):
			username_error = "Please enter a valid user name"
			valid_form = False
		if not valid_password(password):
			password_error = "Please enter a valid password"
			valid_form = False

		if valid_form:
			cookie_val = make_secure_val(user_name)
			self.response.set_cookie('name', cookie_val)
			self.redirect('/welcome')
		else:
			self.render('login.html',
				username=user_name,
				username_error=username_error,
				password_error=password_error)


class LogoutHandler(Handler):
	"""Clears the cookie set by either the login or signup page, then
	redirects back to the signup page."""
	def get(self):
		user_name_cookie = self.request.cookies.get('name')
		if user_name_cookie:
			self.response.set_cookie('name', '', expires=datetime.datetime.min)
		self.redirect('/signup')


class WelcomeHandler(Handler):
	"""Greets a user who has signed up or logged in, using the set cookie
	to display their username.  If the cookie is invalid, redirects
	to the signup page"""
	def get(self):
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if user:
			self.render('welcome.html', user=user)
		else:
			self.redirect('/signup')


class BlogEntry(db.Model):
	"""Creates an entity for storing blog entries"""
	title 	= db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)


class Blog(Handler):
	"""Serves the front page of the blog, 
	displaying most recent entries first"""
	def get(self):
		posts = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY created DESC limit 10")
		cookie = self.request.cookies.get('name')
		user = check_login(cookie)
		self.render('blog.html', user=user, posts=posts)


class SinglePost(Handler):
	"""Displays an individual blog post as identified in the URL"""
	def get(self, post_id):
		post = BlogEntry.get_by_id(int(post_id))
		if post:
			self.render("permalink.html", post=post)
		else:
			self.error(404)
			return


class NewBlogPost(Handler):
	"""Accepts and stores new blog posts"""
	def get(self):
		cookie = self.request.cookies.get('name')
		user = check_login(cookie)
		if user:
			self.render("newpost.html", user=user)
		else:
			self.redirect("/signup")

	def post(self):
		title = self.request.get("subject")
		content = self.request.get("content")
		cookie = self.request.cookies.get('name')
		user = check_login(cookie)
		if title and content:
			post = BlogEntry(title=title, content=content)
			post.put()
			post_id = post.key().id()
			self.redirect('/blog/%s' % post_id)
		else:
			error = "You must include both a title and content"
			self.render("/newpost", 
				title=title, content=content, 
				error=error, user=user)


app = webapp2.WSGIApplication([
	('/', Blog),
    ('/ascii', Ascii),
    ('/blog', Blog),
    ('/blog/newpost', NewBlogPost),
    ('/blog/(\w+)', SinglePost),
    ('/food', FoodHandler),
    ('/fizzbuzz', FizzBuzzHandler),
    ('/rot13', Rot13Handler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler)
    ], debug=True)


'''
TODO:
	- add login button to all necessary pages
	- add logout button to all necessary pages
	- add signin button to all necessary pages
	- if needed, restructure templates to allow for these buttons
	- add redirect links to all pages for easier navigation
	- ? add edit button to each blog post ?
	- restructure templates to separate concerns

	- Fix issue with url_for() in templates
'''