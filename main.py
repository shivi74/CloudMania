import uuid
import cgi
import webapp2
import jinja2
import re
import os
import base64
import urllib
import datetime

from google.appengine.api import users
from google.appengine.ext import db

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class User(db.Model):
  email = db.StringProperty(required = True)
  password = db.StringProperty(required = True)
  creation = db.DateTimeProperty(auto_now_add=True)
  
class Verify(db.model):
  email = db.StringProperty(required = True)
  uuid = db.StringProperty(required = True)
  is_verify = db.BoolenProperty()

class Forgot(db.model):
  email = db.StringProperty(required = True)
  is_viewed = db.BoplenPropery()
  password = db.TextProperty()
  
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)
	
class MainPage(webapp2.RequestHandler):
  def get(self):
    template_values = {"email":"","email_error":"","password":"","confirm password":""}
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.out.write(template.render(template_values))

  def post(self):
	user_email = self.request.get('email')
	user_password = self.request.get('password')
	user_cpassword = self.request.get('confirm password')	
	user_creation = self.request.get('creation')
	geted_email_error = ""
	if (user_email and valid_email(user_email)) and (user_password and user_cpassword):
		a = User(email = user_email,
				password = base64.b64encode('user_password'),
				creation = user_creation)
		a.put()
	else:
          geted_email_error = "e-mail is not valid!"
	  template_values = {"email": user_email,"email_error": geted_email_error}
        template = jinja_environment.get_template('index.html')
        self.response.out.write(template.render(template_values))
	self.redirect('/vefiry')

class NextPage(webapp2.RequestHandler):

    def get(self):
        
		template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render(template_values))
		
	def post(self)
		user_email = self.request.get('email')
		user_uuid = uuid.uuid4(user_email)
		
class VerifyHandler(webapp2.RequestHandler):

    def get(self, uuid):
	template_values = {"email":"","uuid":"","is_verify":""}
	template = JINJA_ENVIRONMENT.get_template('index.html')
	self.response.write(template.render({'firstname': uuid, 'lastname': self.request.get('q', 'nothing')}))
	
	def post(self)
		user_email = self.request.get('email')
		user_uuid = uuid.UUID(user_email)
		

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/next', NextPage),
    (r'/verify/(.*)$', VerifyHandler),
], debug=True)
