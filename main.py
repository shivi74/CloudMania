import uuid
import cgi
import webapp2
import jinja2
import logging
import os
import base64
import urllib
import datetime
import smtplib
import database
import utils

from google.appengine.api import users
from google.appengine.api import mail

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

def showIndex(handler, values):
  template = JINJA_ENVIRONMENT.get_template('index.html')
  handler.response.out.write(template.render(values))

class MainPage(webapp2.RequestHandler):
  def get(self):
  	showIndex(self, {})

class RegisterHandler(webapp2.RequestHandler):

  def get(self):
    self.redirect('/')

  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email','')
    logging.info(utils.valid_email(user_email))
    user_password = self.request.get('password')
    user_cpassword = self.request.get('confirmpassword')
    q = database.Query(database.User)
    q.filter("email =", user_email)
    total = q.count()
    logging.info(total)
    if ((user_email and utils.valid_email(user_email)) and (user_password == user_cpassword) and total == 0):
      database.User(email=user_email, password=base64.b64encode(user_password)).put()
      self.redirect('/login#banner')
      return
    else:
      errors = []
      if(total !=0):
        errors.append("Email address already exists!")
      elif(user_email or utils.valid_email(user_email)):
        errors.append("Email Address is not valid!")
      if(user_password != user_cpassword):
      	errors.append("Password and Confirm password doesn't match!")
      logging.info(errors)
    template_values = {"errors": "<br/>".join(errors)}
    showIndex(self, template_values)
    self.redirect('/verify')

class VerifyHandler(webapp2.RequestHandler):

  def get(self):
    self.redirect('/')

  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email')
    user_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, 'user_email')
    logging.info(user_uuid)
    database.Verify(email=user_email, uuid=user_uuid, is_verify="false").put();
    mail.send_mail(sender='shivani.9487@gmail.com',
              to=user_email,
              subject="CloudMania Verification mail",
              body="""
    Dear User:
    
    Hello, Thank you for registering in cloudmania.

    Please tap the following link to complete the email registration process.
    http://www.cloudmania.in/verify?%s\n\n""" % (Verify.user_uuid)
    
    )
    logging.info(mail.send_mail)
    user_uuidg = self.request.get('user_uuid')
    logging.info(user_uuidg)
    if (user_uuid and user_uuidg):
      Verify(email=user_email, uuid=user_uuid, is_verify="true").put();
      print "Verification Successfull."
    else:
      errors = []
      if(not Verify.is_verify):
        errors.append("User not Verified!")
    template_values = {"email":"","uuid":"","is_verify":""}
    showIndex(self, template_values)
    self.redirect('/login')

class LoginHandler(webapp2.RequestHandler):

  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'login': True}))

  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email', '')
    is_valid = utils.valid_email(user_email)
    errors = []
    if (is_valid):
      user_password = self.request.get('password', '')
      q = database.Query(database.User)
      q.filter("email =", user_email)
      record = q.fetch(1)
      logging.info(record[0].password)
      logging.info(base64.b64encode(user_password))
      logging.info(user_password)
      if(base64.b64encode(user_password) == record[0].password):
        template_values = {'login': True, 'user': record[0].email}
    if( not is_valid):
      errors.append('Wrong Username / Password!')
      template_values = {'errors': '<br/>'.join(errors), 'login': True}
    showIndex(self, template_values)
    
class ForgotHandler(webapp2.RequestHandler):
    
  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'forgot': True}))
      
  def post(self):
    logging.info(self.request)
    user_email = self.request.get('email')
    user_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, 'user_email')
    logging.info(user_uuid)
    database.Verify(email=user_email, uuid=user_uuid, is_viewed="false").put();
    mail.send_mail(sender='shivani.9487@gmail.com',
              to=user_email,
              subject="CloudMania Reset Password",
              body="""
    Dear User:
    
    Hello, Please tap the following link to change password.
    http://www.cloudmania.in/forgotpassword?%s\n\n""" % (Forgot.user_uuid)
    
    )
    logging.info(mail.send_mail)
    user_uuidg = self.request.get('user_uuid')
    logging.info(user_uuidg)
    if (user_uuid and user_uuidg):
      user_password = self.request.get('password')
      Forgot(email=user_email, password=base64.b64encode(user_password), uuid=user_uuid, is_viewed="true").put();
      print "Password Changed."
    else:
      errors = []
      if(not Forgot.is_viewed):
        errors.append("Password cannot be changed!")
    template_values = {"email":"","uuid":"","is_viewed":""}
    
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/verify', VerifyHandler),
    ('/register', RegisterHandler),
    ('/login', LoginHandler),
    ('/forgot', ForgotHandler)
], debug=True)
