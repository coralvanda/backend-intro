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


def valid_username(username):
	"""Confirms that a given username conforms to my requirements"""
	user_re = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
	return user_re.match(username)

def valid_password(password):
	"""Confirms that a given password conforms to my requirements"""
	pw_re = re.compile(r"^.{3,20}$")
	return pw_re.match(password)

def valid_email(email):
	"""Confirms that a given email is probably valid"""
	email_re = re.compile(r'^[\S]+@[\S]+.[\S]+$')
	return email_re.match(email)

def hash_str(s):
	"""Returns an hmac-hashed version of the input string"""
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	"""Returns the given string and its hashed version as a 
	single string"""
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	"""Confirms that a given string/hash pair is valid"""
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_salt(length=5):
	"""Creates/returns a string of random letters, 5 by default"""
	return "".join(random.choice(string.letters) for x in range(length))

def make_pw_hash(name, pw, salt=None):
	"""Uses salt to make a more secure password hash"""
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	"""Verifies that a password is valid using the hash"""
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	"""Returns the user's database key"""
	return db.Key.from_path('users', group)

def check_login(cookie):
	"""Checks for a logged-in user based on the stored cookie, 
	and returns the username if logged in"""
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
		"""Takes in a user ID, returns that user if present"""
		return User.get_by_id(uid, parent = user_key())

	@classmethod
	def by_name(cls, name):
		"""Takes in a user name, returns that user if present"""
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		"""Takes in user registration info, returns a user
		DB model object"""
		pw_hash = make_pw_hash(name, pw)
		return User(parent=users_key(),
			name=name,
			pw_hash=pw_hash,
			email=email)

	@classmethod
	def login(cls, name, pw):
		"""Takes in login info, and returns that user if 
		the login info is valid"""
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


class SignupHandler(Handler):
	"""Allows a user to signup, enforcing rules for username, 
	password and allowing an optional email input (also checked 
	for validity). Then sets a cookie and sends the user to the 
	welcome page"""
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
	"""Allows users to log in, enforcing rules for username and 
	password. If valid, sets a cookie and redirects to the 
	welcome page."""
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
	"""Greets a user who has signed up or logged in, using the 
	set cookie to display their username.  If the cookie is 
	invalid, it redirects to the signup page"""
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
	creator = db.StringProperty(required=True)
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
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if post:
			self.render("permalink.html", post=post, user=user)
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
		title 	= self.request.get("subject")
		content = self.request.get("content")
		cookie 	= self.request.cookies.get('name')
		user 	= check_login(cookie)
		if title and content and user:
			post = BlogEntry(title=title, 
							content=content,
							creator=user)
			post.put()
			post_id = post.key().id()
			self.redirect("/blog/%s" % post_id)
		else:
			error = "You must include both a title and content"
			self.render("/newpost.html", 
				title=title, content=content, 
				error=error, user=user)


class EditBlogPost(Handler):
	"""Accepts a post ID, and allows the creator to edit it.
	If a user other than the creator tries, they receive an error"""
	def get(self, post_id):
		post = BlogEntry.get_by_id(int(post_id))
		if not post:
			self.error(404)
			return
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if not user or post.creator != user:
			self.error(403)
			self.redirect("/login")
		self.render("/editpost.html", post=post, post_id=post_id)

	def post(self):
		post_id = self.request.get("post_id")
		title	= self.request.get("subject")
		content	= self.request.get("content")
		cookie 	= self.request.cookies.get("name")
		user 	= check_login(cookie)
		if title and content and user:
			post = BlogEntry.get_by_id(int(post_id))
			post.title = title
			post.content = content
			post.creator = user
			post.put()
			self.redirect("/blog/%s" % post_id)
		else:
			error = "You must include both a title and content"
			self.render("/editpost.html", 
				post=post, post_id=post_id)


app = webapp2.WSGIApplication([
	('/', Blog),
    ('/blog', Blog),
    ('/blog/newpost', NewBlogPost),
    ('/blog/(\w+)', SinglePost),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler)
    ], debug=True)


'''
TODO:
	- add edit and delete buttons to each blog post 
		but only for the user who created that post
	- users can like/unlike posts, but receive an error
		if they try to like their own post
	- users can comment on posts
	- restructure templates to separate concerns

	- Getting badvalueerror after trying to implement edit feature
'''