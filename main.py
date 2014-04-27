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
from webapp2_extras import sessions

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

CONFIG = {}
CONFIG['webapp2_extras.sessions'] = dict(secret_key='cloudmaniadotcom')

def showIndex(handler, values):
  template = JINJA_ENVIRONMENT.get_template('index.html')
  handler.response.out.write(template.render(values))

class BaseHandler(webapp2.RequestHandler):
  def dispatch(self):
    """
      This snippet of code is taken from the webapp2 framework documentation.
      See more at
      http://webapp-improved.appspot.com/api/webapp2_extras/sessions.html
      """
    self.session_store = sessions.get_store(request=self.request)
    try:
      webapp2.RequestHandler.dispatch(self)
    finally:
      self.session_store.save_sessions(self.response)

  @webapp2.cached_property
  def session(self):
    """
      This snippet of code is taken from the webapp2 framework documentation.
      See more at
      http://webapp-improved.appspot.com/api/webapp2_extras/sessions.html
      """
    return self.session_store.get_session()

class MainPage(BaseHandler):
    
  def get(self):
      showIndex(self, {})

class RegisterHandler(BaseHandler):

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
      user_uuid = str(uuid.uuid1())
      logging.info(user_uuid)
      user_obj = database.User(key_name = user_email, email = user_email, password = base64.b64encode(user_password), is_verify = False)
      user_obj.put()
      database.Verify(user=user_obj, uuid=user_uuid).put()
      sender = 'shivani.9487@gmail.com'
      to = user_email
      mail.send_mail(sender = sender,
                     to = user_email,
                     subject = "CloudMania Verification mail",
                     body="""
                         Dear User:
                         Hello, Thank you for registering in cloudmania.
                         Please tap the following link to complete the email registration process.
                         http://cloud-mania.appspot.com/verify?uuid=%s\n\n""" % (user_uuid))
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

class VerifyHandler(BaseHandler):

  def get(self):
    errors = []
    logging.info(self.request)
    user_uuidg = self.request.get('uuid')
    verify_obj = database.Verify.all()
    verify_obj.filter("uuid =", user_uuidg)
    counter = verify_obj.count(limit=1)
    if (counter == 0):
      errors.append("No entry of uuid in database.")
    else:
      verify_objs = verify_obj.run(limit=1)
      verify_objs.is_verify = True
      verify_objs.put()
      success = []
      success.append("Verification Successfull!")
    if(not database.Verify.is_verify):
        errors.append("User not Verified!")
    template_values = {"errors": "<br/>".join(errors),"email":""}
    showIndex(self, template_values)
    self.redirect('/login')

class LoginHandler(BaseHandler):

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
      logging.info(user_email)
      record = q.fetch(1)
      logging.info(record[0].password)
      logging.info(base64.b64encode(user_password))
      logging.info(user_password)
    if (base64.b64encode(user_password) == record[0].password):
      template_values = {'login': True, 'user': record[0].email}
      if(base64.b64encode(user_password) == record[0].password):
        self.session['user'] = user_email
        logging.info("%s just logged in" % user_email)
        template_values = {'login': True, 'user': record[0].email}
    if (not is_valid):
      errors.append('Wrong Username / Password!')
      template_values = {'errors': '<br/>'.join(errors), 'login': True}
    showIndex(self, template_values)

class ForgotHandler(BaseHandler):

  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'forgot': True}))

  def post(self):
    success = []
    errors = []
    logging.info(self.request)
    user_email = self.request.get('email')
    is_valid = utils.valid_email(user_email)
    is_exist = database.User.all().filter("email =", user_email)
    if (not is_exist):
      errors.append('email-id not registered!')
      template_values = {'errors': '<br/>'.join(errors), 'forgot': True}
    if (not is_valid):
      errors.append('Wrong email-id!')
      template_values = {'errors': '<br/>'.join(errors), 'forgot': True}
    if (is_valid and is_exist):
      user_uuid = str(uuid.uuid1())
      logging.info(user_uuid)
      database.Forgot(email = user_email, uuid = user_uuid, is_viewed = False).put();
      mail.send_mail(sender='shivani.9487@gmail.com',
              to = user_email,
              subject="CloudMania Reset Password",
              body="""
    Dear User,

    Hello, Please tap the following link to change password.
    http://cloud-mania.appspot.com/reset?uuid=%s\n\n""" % (user_uuid))
      logging.info(user_uuid)
      template_values = {'message': True}
    template_values = {'errors': '<br/>'.join(errors), "email":"", "password":"", "confirmpassword":"", 'forgot': True, 'message': True}
    showIndex(self, template_values)


class ResetHandler(BaseHandler):
  
  def get(self):
    logging.info(self.request)
    template = JINJA_ENVIRONMENT.get_template('index.html')
    user_uuidg = self.request.get('uuid')
    self.response.write(template.render({'forgot': True, 'reset': True, "uuid": user_uuidg}))
    
  def post(self):
    success = []
    errors = []
    user_email = self.request.get('email')
    user_uuidg = self.request.get('uuid')
    user_password = self.request.get('password','')
    user_cpassword = self.request.get('confirmpassword','')
    logging.info(user_uuidg)
    reset_obj = database.User.all().filter("email =", user_email)
    if (database.Forgot.uuid and str(user_uuidg)):
      if ((user_password and user_cpassword) and database.Forgot.is_viewed == False):
        success.append("Password Changed !")
        template_values = {'success': '<br/>'.join(success), 'forgot': True, 'reset': True}
        reset_objs = reset_obj.run(limit=1)
        reset_objs.password = base64.b64encode(user_password).put()
        database.Forgot(email = user_email, uuid = user_uuid, is_viewed = True).put();
      else:
        errors.append("Password don't match!")
        template_values = {'errors': '<br/>'.join(errors), 'forgot': True, 'reset': True}
      self.redirect('/login')
    else:
      if(not database.Forgot.is_viewed):
        errors.append("Password cannot be changed!")
    template_values = {'success': '<br/>'.join(success), 'errors': '<br/>'.join(errors), "email":"", "password":""}
    showIndex(self, template_values)
  

class ChangepasswordHandler(BaseHandler):

  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'user': True, 'changepassword': True}))

  def post(self):
    logging.info(self.request)
    user = self.session.get('User')
    errors = []
    user_password = self.request.get('password', '')
    if ((database.User.password and user_password) and user):
      user_npassword = self.request.get('npassword', '')
      user_cpassword = self.request.get('confirmpassword', '')
      logging.info(base64.b64encode(user_password))
      logging.info(user_npassword)
      if (user_npassword and user_cpassword):
        success = []
        success.append("Password changed !")
        database.User(email = user_email, password=base64.b64encode(user_npassword)).put();
      else:
        errors.append("Password don't match!")
    else:
      errors.append("Old Password don't match!")
      template_values = {'errors': '<br/>'.join(errors),'user': True, 'changepassword': True}
    showIndex(self, template_values)

class AddsiteHandler(BaseHandler):
    
  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'user': True, 'addsite': True}))
    
  def post(self):
    logging.info(self.request)
    user = self.session.get('user')
    errors = []
    success = []
    user_sitename = self.request.get('sitename', '')
    user_siteID = self.request.get('siteID', '')
    if( user_siteID == "" ):
      errors.append("Don't forget to give siteID!")
      template_values = {'errors': '<br/>'.join(errors),'user': True, 'addsite' : True}
    idobj = database.Addsite.all()
    idobj.filter("siteID =", user_siteID)
    counter = idobj.count(limit=1)
    if (counter == 0):
      success.append("Password changed !")
      database.Addsite(sitename = user_sitename, siteID = user_siteID).put()
      template_values = {'success': '<br/>'.join(success), 'user' : True}
    else:
      errors.append("ID already exist!! Try another :)")
      template_values = {'errors': '<br/>'.join(errors), 'user' : True,'addsite' : True}
      self.redirect('/addsite')
    showIndex(self, template_values)

class LogoutHandler(BaseHandler):

  def get(self):
    self.post()

  def post(self):
    logging.info(self.request)
    self.session["user"] = None
    user = users.get_current_user()
    if user:
      users.create_logout_url(self.request.uri)
    else:
      self.redirect('/login')
    template_values = {'logout': True}
    showIndex(self, template_values)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/verify', VerifyHandler),
    ('/register', RegisterHandler),
    ('/login', LoginHandler),
    ('/forgot', ForgotHandler),
    ('/reset', ResetHandler),
    ('/changepassword', ChangepasswordHandler),
    ('/addsite', AddsiteHandler),
    ('/logout', LogoutHandler)
], debug=True, config=CONFIG)
