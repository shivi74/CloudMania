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
    if ((user_email and utils.valid_email(user_email))
    		and (user_password == user_cpassword) and total == 0):
      database.User(
      	email=user_email, password=base64.b64encode(user_password)).put()
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
      showIndex(template_values)


class VerifyHandler(webapp2.RequestHandler):

  def get(self):
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
    database.Verify(email=user_email, uuid=user_uuid, is_verify="false").put();
    user_uuidg = self.request.get('user_uuid')
    if (user_uuid and user_uuidg):
      Verify(email=user_email, uuid=user_uuid, is_verify="true").put();
    else:
      errors = []
      if(not Verify.is_verify):
        errors.append("User not Verified!")
    template_values = {"email":"","uuid":"","is_verify":""}
    showIndex(template_values)


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
    showIndex(template_values)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/verify', VerifyHandler),
    ('/register', RegisterHandler),
    ('/login', LoginHandler),
], debug=True)
