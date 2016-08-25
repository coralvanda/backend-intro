import random
import string
import hashlib

from google.appengine.ext import ndb


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
	#return ndb.Key.from_path('users', group)
	return ndb.Key('users', group)


class User(ndb.Model):
	"""Creates an entity for storing users and provides
	functionality for finding and handling users"""
	name = ndb.StringProperty(required=True)
	pw_hash = ndb.StringProperty(required=True)
	email = ndb.StringProperty()

	@classmethod
	def _by_id(cls, uid):
		"""Takes in a user ID, returns that user if present"""
		return User.get_by_id(uid, parent = user_key())

	@classmethod
	def _by_name(cls, name):
		"""Takes in a user name, returns that user if present"""
		u = User.query(User.name == name).get()
		return u

	@classmethod
	def _register(cls, name, pw, email = None):
		"""Takes in user registration info, returns a user
		DB model object"""
		pw_hash = make_pw_hash(name, pw)
		return User(parent=users_key(),
			name=name,
			pw_hash=pw_hash,
			email=email)

	@classmethod
	def _login(cls, name, pw):
		"""Takes in login info, and returns that user if 
		the login info is valid"""
		u = cls._by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


class BlogEntry(ndb.Model):
	"""Creates an entity for storing blog entries"""
	title 		= ndb.StringProperty(required=True)
	content 	= ndb.TextProperty(required=True)
	creator 	= ndb.StringProperty(required=True)
	liked		= ndb.StringProperty(repeated=True)
	created 	= ndb.DateTimeProperty(auto_now_add=True)


class Comment(ndb.Model):
	"""Creates an entity for storing comments on blog entries"""
	content		= ndb.TextProperty(required=True)
	creator		= ndb.StringProperty(required=True)
	created		= ndb.DateTimeProperty(auto_now_add=True)
	parent_post = ndb.StringProperty(required=True)