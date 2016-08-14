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


app = webapp2.WSGIApplication([
	('/', Ascii),
    ('/ascii', Ascii),
    ('/food', FoodHandler),
    ('/fizzbuzz', FizzBuzzHandler),
    ('/rot13', Rot13Handler),
    ], debug=True)