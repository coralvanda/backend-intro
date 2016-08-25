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
import hmac
import Cookie
import datetime

from google.appengine.ext import ndb

from models import User
from models import BlogEntry
from models import Comment

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

def check_login(cookie):
	"""Checks for a logged-in user based on the stored cookie, 
	and returns the username if logged in"""
	if not cookie:
		return False
	else:
		return check_secure_val(cookie)


class SignupHandler(Handler):
	"""Allows a user to signup.

	Enforces rules for username, password and allows an optional 
	email input, which is also checked for validity. Then sets a 
	cookie and sends the user to the welcome page"""
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

		u = User._by_name(user_name)
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
			u = User._register(user_name, password, email)
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
	"""Allows users to log in.

	Enforces rules for username and password. If valid, sets 
	a cookie and redirects to the welcome page."""
	def get(self):
		self.render('login.html')

	def post(self):
		user_name	= self.request.get('username')
		password 	= self.request.get('password')
		username_error 	= ''
		password_error 	= ''
		valid_form = True

		u = User._login(user_name, password)
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
	"""Clears the cookie set by the login or signup page."""
	def get(self):
		user_name_cookie = self.request.cookies.get('name')
		if user_name_cookie:
			self.response.set_cookie('name', '', expires=datetime.datetime.min)
		self.redirect('/signup')


class WelcomeHandler(Handler):
	"""Greets a user.

	Only available to those who have signed up or logged in.  
	Uses the set cookie to display their username.  If the 
	cookie is invalid, it redirects to the signup page"""
	def get(self):
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if user:
			self.render('welcome.html', user=user)
		else:
			self.redirect('/signup')


class Blog(Handler):
	"""Serves the blog's front page, displays most recent entries first"""
	def get(self):
		posts = ndb.gql("SELECT * FROM BlogEntry ORDER BY created DESC limit 10")
		cookie = self.request.cookies.get('name')
		user = check_login(cookie)
		self.render('blog.html', user=user, posts=posts)


class SinglePost(Handler):
	"""Displays an individual blog post as identified in the URL.

	Displays any comments made on this post, also allows for 
	comments to be created for this blog entry, using the 
	post method."""
	def get(self, post_id):
		blog_post = BlogEntry.get_by_id(int(post_id))
		comments = Comment.query(Comment.parent_post==post_id).fetch()
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if blog_post:
			self.render("permalink.html", 
				blog_post=blog_post, post_id=post_id, 
				comments=comments, user=user)
		else:
			self.error(404)
			return

	def post(self, post_id):
		content = self.request.get("content")
		cookie 	= self.request.cookies.get('name')
		user 	= check_login(cookie)
		blog_post = BlogEntry.get_by_id(int(post_id))
		comments = Comment.query(Comment.parent_post==post_id).fetch()
		if not user:
			self.redirect("/signup")
		elif content:
			comment = Comment(content=content,
							creator=user,
							parent_post=post_id)
			comment.put()
			self.redirect("/blog")
			# Could not figure out how to re-render the same page
			# while updating with the new post for some reason
			# so this is my work-around
		else:
			error = "You must include content"
			self.render("/permalink.html",
				blog_post=blog_post, post_id=post_id,
				comments=comments, content=content, 
				error=error, user=user)


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
			blog_post = BlogEntry(title=title, 
							content=content,
							creator=user)
			blog_post.put()
			post_id = blog_post.key.id()
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
		blog_post = BlogEntry.get_by_id(int(post_id))
		if not blog_post:
			self.error(404)
			return
		title = blog_post.title
		content = blog_post.content
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if not user:
			self.error(403)
			self.redirect("/login")
		elif blog_post.creator != user:
			self.render("/blog.html", user=user,
				error="May only edit your own posts")
		else:
			self.render("/editpost.html", 
				title=title, content=content)

	def post(self, post_id):
		title	= self.request.get("subject")
		content	= self.request.get("content")
		cookie 	= self.request.cookies.get("name")
		user 	= check_login(cookie)
		if title and content and user:
			blog_post = BlogEntry.get_by_id(int(post_id))
			blog_post.title = title
			blog_post.content = content
			blog_post.creator = user
			blog_post.put()
			self.redirect("/blog/%s" % post_id)
		else:
			error = "You must include both a title and content"
			self.render("/editpost.html", 
				title=title, content=content, error=error)


class DeletePost(Handler):
	"""Accepts a post ID, and deletes it from the DB.

	If a user other than the creator tries, they receive an error"""
	def get(self, post_id):
		blog_post = BlogEntry.get_by_id(int(post_id))
		if not blog_post:
			self.error(404)
			return
		user_name_cookie = self.request.cookies.get("name")
		user = check_login(user_name_cookie)
		if not user:
			self.redirect("/login")
		elif blog_post.creator != user:
			self.error(403)
			self.render("/blog.html", user=user,
				error="May only delete your own posts")
		else:
			blog_post.key.delete()
			self.render("/deleted.html")


class LikePost(Handler):
	"""Accepts a post ID and allows a user to like a post.

	If the user is not logged in, if it's his own post,
	or if he has already liked the post, he will be redirected."""
	def get(self, post_id):
		blog_post = BlogEntry.get_by_id(int(post_id))
		if not blog_post:
			self.error(404)
			return
		user_name_cookie = self.request.cookies.get("name")
		user = check_login(user_name_cookie)
		if not user:
			self.redirect("/login")
		elif blog_post.creator == user:
			self.error(403)
			self.render("/blog.html", user=user,
				error="Cannot like your own posts")
		elif user in blog_post.liked:
			self.render("/blog.html", user=user,
				error="May only like a post one time")
		else:
			blog_post.liked.append(user)
			blog_post.put()
			self.redirect("/blog/" + post_id)


class EditComment(Handler):
	"""Accepts a comment ID, and allows the creator to edit it.
	
	If a user other than the creator tries, they receive an error"""
	def get(self, comment_id):
		comment = Comment.get_by_id(int(comment_id))
		if not comment:
			self.error(404)
			return
		content = comment.content
		user_name_cookie = self.request.cookies.get('name')
		user = check_login(user_name_cookie)
		if not user:
			self.error(403)
			self.redirect("/login")
		elif comment.creator != user:
			self.render("/blog.html", user=user,
				error="May only edit your own posts")
		else:
			self.render("/editcomment.html", 
				content=content)

	def post(self, comment_id):
		content	= self.request.get("content")
		cookie 	= self.request.cookies.get("name")
		user 	= check_login(cookie)
		if not user:
			self.redirect("/login")
		elif content:
			comment = Comment.get_by_id(int(comment_id))
			comment.content = content
			comment.creator = user
			comment.put()
			self.redirect("/blog")
		else:
			error = "You must include content"
			self.render("/editcomment.html", 
				content=content, user=user, error=error)


class DeleteComment(Handler):
	"""Accepts a comment ID, and deletes it from the DB.

	If a user other than the creator tries, they receive an error"""
	def get(self, comment_id):
		comment = Comment.get_by_id(int(comment_id))
		if not comment:
			self.error(404)
			return
		user_name_cookie = self.request.cookies.get("name")
		user = check_login(user_name_cookie)
		if not user:
			self.redirect("/login")
		elif comment.creator != user:
			self.error(403)
			self.render("/blog.html", user=user,
				error="May only delete your own posts")
		else:
			comment.key.delete()
			self.render("/deleted.html")


app = webapp2.WSGIApplication([
	('/', Blog),
    ('/blog', Blog),
    ('/blog/newpost', NewBlogPost),
    ('/blog/edit/(\w+)', EditBlogPost),
    ('/blog/delete/(\w+)', DeletePost),
    ('/blog/like/(\w+)', LikePost),
    ('/blog/(\w+)', SinglePost),
    ('/comment/edit/(\w+)', EditComment),
    ('/comment/delete/(\w+)', DeleteComment),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler)
    ], debug=True)


'''
TODO:
	- users can comment on posts
		FIX: line 439 is not finding the entity I want using
		that query, need to figure out how to find it

	- remove post_id=post_id from editpost handler?
'''