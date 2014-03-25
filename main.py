import uuid
import cgi
import webapp2
import jinja2
import logging
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
  created = db.DateTimeProperty(auto_now_add=True)
  updated = db.DateTimeProperty(auto_now=True)
  
class Verify(db.Model):
  email = db.StringProperty(required = True)
  uuid = db.StringProperty(required = True)
  is_verify = db.BooleanProperty()

class Forgot(db.Model):
  email = db.StringProperty(required = True)
  is_viewed = db.BooleanProperty()
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
    if (user_email and valid_email(user_email)) and (user_password == user_cpassword):
      a = User(email = user_email,
          password = base64.b64encode('user_password'),
          creation = user_creation)
      a.put()
    else:
      geted_email_error = "e-mail is not valid!"
      template_values = {"email": user_email,"email_error": geted_email_error}
      template = JINJA_ENVIRONMENT.get_template('index.html')
      self.response.out.write(template.render(template_values))
      return
    self.redirect('/vefiry')

class NextPage(webapp2.RequestHandler):
  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render(template_values))

  def post(self):
    user_email = self.request.get('email')
    user_uuid = uuid.uuid4(user_email)
		
class VerifyHandler(webapp2.RequestHandler):

  def get(self, uuid):
    template_values = {"email":"","uuid":"","is_verify":""}
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'firstname': uuid, 'lastname': self.request.get('q', 'nothing')}))

  def post(self):
    user_email = self.request.get('email')
    user_uuid = uuid.UUID(user_email)

class RegisterHandler(webapp2.RequestHandler):

  def get(self):
    self.redirect('/')

  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email','')
    logging.info(valid_email(user_email))
    user_password = self.request.get('password')
    user_cpassword = self.request.get('confirmpassword')
    q = db.Query(User)
    q.filter("email =", user_email)
    total = q.count()
    logging.info(total)
    if (user_email and valid_email(user_email)) and (user_password == user_cpassword) and total == 0:
	User(email=user_email, password=user_password).put();
    	self.redirect('/#banner')
	return
    else:
      errors = []
      if(total !=0):
	errors.append("Email address already exists!")
      elif(user_email or valid_email(user_email)):
        errors.append("Email Address is not valid!")
      if(user_password != user_cpassword):
      	errors.append("Password and Confirm password doesn't match!")
      logging.info(errors)
      template_values = {"errors": "<br/>".join(errors)}
      template = JINJA_ENVIRONMENT.get_template('index.html')
      self.response.out.write(template.render(template_values))
      return

class LoginHandler(webapp2.RequestHandler):
  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email', '')
    is_valid = valid_email(user_email)
    errors = []
    if (is_valid):
    	user_password = self.request.get('password', '')
	q = db.Query(User)
	q.filter("email =", user_email)
	record = q.fetch(1)
	logging.info(record[0])
	logging.info(dir(record[0]))
	if(user_password == record[0].password):
	  template_values = {'login': True, 'user': record[0].email}
    if( not is_valid):
	errors.append('Wrong Username / Password!')
	template_values = {'errors': '<br/>'.join(errors), 'login': True}
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.out.write(template.render(template_values))

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/next', NextPage),
    (r'/verify/(.*)$', VerifyHandler),
    ('/register', RegisterHandler),
    ('/login', LoginHandler),
], debug=True)
