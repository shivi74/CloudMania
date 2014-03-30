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
import smtplib

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
    self.redirect('/')

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
      User(email=user_email, password=base64.b64encode('user_password')).put();
      self.redirect('/verify')
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

class VerifyHandler(webapp2.RequestHandler):

  def get(self, uuid):
    self.redirect('/')

  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email')
    user_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, 'user_email')
    logging.info(user_uuid)
    server = smtplib.SMTP('smtp.gmail.com', 587)
    #Next, log in to the server
    server.login("shivani.9487@gmail.com", "SuppermaN")
    #Send the mail
    msg = "\nHello! Click on the following link to verify: \n "
    link = "cloudmania.in/verify/?uuid=" + user_uuid
    server.sendmail("shivani.9487@gmail.com", "user_email", msg + link)
    Verify(email=user_email, uuid=user_uuid, is_verify="false").put();
    user_uuidg = self.request.get('user_uuid')
    if (user_uuid and user_uuidg):
      Verify(email=user_email, uuid=user_uuid, is_verify="true").put();
    else:
      errors = []
      if(not Verify.is_verify):
        errors.append("User not Verified!")
    template_values = {"email":"","uuid":"","is_verify":""}
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render(template_values))
    
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
    if(not is_valid):
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
