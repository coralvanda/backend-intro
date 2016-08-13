import os
import sys
from google.appengine.ext import vendor

vendor.add('lib')

if os.environ.get('SERVER_SOFTWARE', '').startswith('Google App Engine'):
	sys.path.insert(0, 'lib.zip')
else:
	if os.name == 'nt':
		os.name = None
		sys.platform = ''