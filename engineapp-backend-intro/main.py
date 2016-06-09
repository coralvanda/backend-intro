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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape = True)


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class MainPage(Handler):
    def get(self):
    	items = self.request.get_all("food")
    	self.render("shopping_list.html", items = items)


class FizzBuzzHandler(Handler):
	def get(self):
		n = self.request.get('n', 0)
		n = n and int(n)
		self.render('fizzbuzz.html', n=n)


class Rot13Handler(Handler):
	def get(self):
		text = self.request.get("text")
		self.render('rot13.html', text=text)

	def post(self):
		text = self.request.get("text")
		encoder = codecs.getencoder("rot-13")
		encoded_text = encoder(text)[0]
		self.render('rot13.html', text=encoded_text)


def valid_username(username):
	user_re = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
	return user_re.match(username)

def valid_password(password):
	pw_re = re.compile(r"^.{3,20}$")
	return pw_re.match(password)

def valid_email(email):
	email_re = re.compile(r'^[\S]+@[\S]+.[\S]+$')
	return email_re.match(email)


class SignupHandler(Handler):
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

		#TODO Fix coloring for errors on signup.html
		# and rendering the welcome page correctly
		if valid_form:
			self.redirect('/welcome?username=%s' % user_name)
		else:
			self.render('signup.html',
				username=user_name,
				email=email, 
				username_error=username_error,
				password_error=password_error,
				verify_error=verify_error,
				email_error=email_error)


class WelcomeHandler(Handler):
	def get(self):
		user_name = self.request.get('username')
		self.render('welcome.html', username=user_name)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/fizzbuzz', FizzBuzzHandler),
    ('/rot13', Rot13Handler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler)
    ], debug=True)
