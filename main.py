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
from dropbox.client import DropboxClient, DropboxOAuth2Flow


from google.appengine.api import users
from google.appengine.api import mail
from webapp2_extras import sessions

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

# Fill these in!
DROPBOX_APP_KEY = 'nyoq9i1tlltl0si'
DROPBOX_APP_SECRET = '3x51jbmxlegpcnv'

CONFIG = {}
CONFIG['webapp2_extras.sessions'] = dict(secret_key='cloudmaniadotcom')

def showIndex(handler, values):
  template = JINJA_ENVIRONMENT.get_template('index.html')
  handler.response.out.write(template.render(values))

def getUser(email):
  users = database.User.all()
  users.filter('email =', email)
  return users.get() if users.count(limit=1) else None

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
    user_obj = self.session.get('User')
    if (user_obj):
      self.redirect('/home')
    else:
      self.redirect('/')
    template = JINJA_ENVIRONMENT.get_template('index.html')

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
                         http://cloud-mania.appspot.com/verify?uuid=%s#banner\n\n""" % (user_uuid))
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
    user = self.session.get('User')
    user_uuidg = self.request.get('uuid')
    verify_all = database.Verify.all()
    verify_all.filter("uuid =", user_uuidg)
    counter = verify_all.count(limit=1)
    if (counter == 0):
      if (user):
        self.redirect('/home')
      else:
        errors.append("User not registered!")
    else:
      verify_record = verify_all.get()
      success = []
      verify_record.user.is_verify = True
      verify_record.user.put()
      verify_record.delete()
      success.append("Verification Successfull!")
    template_values = {"success": '<br/>'.join(success), "errors": "<br/>".join(errors)}
    showIndex(self, template_values)

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
      q = database.User.all()
      q.filter("email =", user_email)
      user_obj = q.get()
    if (base64.b64encode(user_password) == user_obj.password):
      template_values = {'login': True, 'user': user_obj.email}
      if(base64.b64encode(user_password) == user_obj.password):
        self.session['user'] = user_email
        logging.info("%s just logged in" % user_email)
        template_values = {'login': True, 'user': user_obj.email}
        self.redirect('/home#banner')
    if (not is_valid):
      errors.append('Wrong Username / Password!')
      template_values = {'errors': '<br/>'.join(errors), 'login': True}
    showIndex(self, template_values)

class HomeHandler(BaseHandler):

  def get(self):
    user_email = self.session.get('user')
    user_obj = getUser(user_email)
    if( not user_obj):
      self.redirect('/login')
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'user': True,
                                         'is_connected': user_obj.access_token}))

  def post(self):
    user_obj = self.session.get('user')
    template_values = {'user': True}
    showIndex(self, template_values)

class ForgotHandler(BaseHandler):

  def get(self):
    user_obj = self.session.get('user')
    if (user):
      self.redirect('/home')
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'forgot': True}))

  def post(self):
    errors = []
    logging.info(self.request)
    user_email = self.request.get('email')
    is_valid = utils.valid_email(user_email)
    user_all = database.User.all().filter("email =", user_email)
    total = user_all.count(limit=1)
    if (total == 0):
      errors.append('email-id not registered!')
      template_values = {'errors': '<br/>'.join(errors), 'forgot': True}
    elif (not is_valid):
      errors.append('Wrong email-id!')
      template_values = {'errors': '<br/>'.join(errors), 'forgot': True}
    else:
      user_uuid = str(uuid.uuid1())
      logging.info(user_uuid)
      database.Forgot(user=user_all.get(), uuid=user_uuid).put()
      mail.send_mail(sender='shivani.9487@gmail.com',
              to = user_email,
              subject="CloudMania Reset Password",
              body="""
    Dear User,

    Hello, Please tap the following link to change password.
    http://cloud-mania.appspot.com/reset?uuid=%s#banner\n\n""" % (user_uuid))
      template_values = {'message': True}
    template_values = {'errors': '<br/>'.join(errors), 'forgot': True, 'message': True}
    showIndex(self, template_values)


class ResetHandler(BaseHandler):

  def get(self):
    logging.info(self.request)
    user_uuidg = self.request.get('uuid')
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'forgot': True, 'reset': True, "uuid": user_uuidg}))

  def post(self):
    success = []
    errors = []
    user_uuidg = self.request.get('uuid')
    user_password = self.request.get('password','')
    user_cpassword = self.request.get('confirmpassword','')
    logging.info(user_uuidg)
    reset_all = database.Forgot.all().filter("uuid =", user_uuidg)
    counter = reset_all.count(limit=1)
    if (counter == 0):
      errors.append("No entry of uuid in database.")
    else:
      if (user_password and user_cpassword):
        reset_record = reset_all.get()
        reset_record.user.password = base64.b64encode(user_password)
        reset_record.user.put()
        reset_record.delete()
        success.append("Password Changed!")
        mail.send_mail(sender='shivani.9487@gmail.com',
              to = reset_record.user.email,
              subject="CloudMania Password Changed",
              body="""
    Dear User,

    Hello, This is to inform you that your CloudMania account's password had been changed successfully.
    Remember to login with new password from now! :)

    -Shivani Sharma""")
        template_values = {'success': '<br/>'.join(success), 'forgot': True, 'login': True}
      else:
        errors.append("Password don't match!")
        template_values = {'errors': '<br/>'.join(errors), 'forgot': True, 'reset': True}
      self.redirect('/login')
    template_values = {'success': '<br/>'.join(success), 'errors': '<br/>'.join(errors)}
    showIndex(self, template_values)


class ChangepasswordHandler(BaseHandler):

  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'user': True, 'changepassword': True}))

  def post(self):
    logging.info(self.request)
    user_obj = self.session.get('user')
    errors = []
    success = []
    user_password = self.request.get('password', '')
    if (user_obj.password and user_password):
      user_npassword = self.request.get('npassword', '')
      user_cpassword = self.request.get('confirmpassword', '')
      if (user_npassword and user_cpassword):
        database.User(password = user_npassword)
        success.append("Password changed !")
        mail.send_mail(sender='shivani.9487@gmail.com',
              to = user_email,
              subject="CloudMania Password Updated",
              body="""
    Dear User,

    Hello, This is to inform you that your CloudMania account's password had been updated successfully.
    Remember to login with new password from now! :)

    -Shivani Sharma""")
    else:
      errors.append("Old Password don't match!")
      self.redirect('/changepassword')
    template_values = {'success': '<br/>'.join(success), 'errors': '<br/>'.join(errors), 'user' : True}
    template_values = {'success': '<br/>'.join(success), 'errors': '<br/>'.join(errors), 'user': True}
    showIndex(self, template_values)

class AddsiteHandler(BaseHandler):

  def get(self):
    template = JINJA_ENVIRONMENT.get_template('index.html')
    self.response.write(template.render({'user': True, 'addsite': True}))

  def post(self):
    logging.info(self.request)
    user_obj = self.session.get('user')
    errors = []
    success = []
    user_sitename = self.request.get('sitename', '')
    user_siteID = self.request.get('siteID', '')
    if( user_siteID == "" ):
      errors.append("Don't forget to give siteID!")
      template_values = {'errors': '<br/>'.join(errors),'user': True, 'addsite' : True}
    idobj = database.Mapping.all()
    idobj.filter("siteID =", user_siteID)
    counter = idobj.count(limit=1)
    if (counter == 0):
      success.append("URL registered!")
      database.Mapping(sitename = user_sitename, siteID = user_siteID).put()
      template_values = {'success': '<br/>'.join(success), 'user' : True}
      self.redirect('/home')
    else:
      errors.append("ID already exist!! Try another :)")
      template_values = {'success': '<br/>'.join(success), 'errors': '<br/>'.join(errors), 'user' : True,'addsite' : True}
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

def get_dropbox_auth_flow(session):
  return DropboxOAuth2Flow(DROPBOX_APP_KEY, DROPBOX_APP_SECRET,
                           'http://localhost:8080/oauth', session,
                           'dropbox-auth-csrf-token')


class ConnectDropboxHandler(BaseHandler):
  def get(self):
    authorize_url = get_dropbox_auth_flow(self.session).start()
    self.redirect(authorize_url)


class DisconnectDropboxHandler(BaseHandler):
  def get(self):
    user_email = self.session.get('user')
    user_obj = getUser(user_email)
    user_obj.access_token = None
    user_obj.put()
    self.redirect('/home#banner')


class OAuthDropboxHandler(BaseHandler):
  def get(self):
    user_email = self.session.get('user')
    logging.info(self.request)
    request_obj = {'state': self.request.get('state'),
                   'code': self.request.get('code')}
    try:
        access_token, user_id, url_state = get_dropbox_auth_flow(self.session).finish(request_obj)
    except DropboxOAuth2Flow.BadRequestException, e:
        logging.info(e)
        logging.info(400)
    except DropboxOAuth2Flow.BadStateException, e:
        logging.info(e)
        logging.info(400)
    except DropboxOAuth2Flow.CsrfException, e:
        logging.info(e)
        logging.info(403)
    except DropboxOAuth2Flow.NotApprovedException, e:
        logging.info(e)
        logging.info('Not approved?  Why not, bro?')
        return self.redirect('/home#banner')
    except DropboxOAuth2Flow.ProviderException, e:
        logging.info("Auth error" + e)
        logging.info(403)
    logging.info(access_token)
    logging.info(user_id)
    logging.info(url_state)
    user_obj = getUser(user_email)
    user_obj.access_token = access_token
    user_obj.put()
    self.redirect('/home#banner')


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/register', RegisterHandler),
    ('/verify', VerifyHandler),
    ('/login', LoginHandler),
    ('/home', HomeHandler),
    ('/forgot', ForgotHandler),
    ('/reset', ResetHandler),
    ('/changepassword', ChangepasswordHandler),
    ('/addsite', AddsiteHandler),
    ('/logout', LogoutHandler),
    ('/connect', ConnectDropboxHandler),
    ('/oauth', OAuthDropboxHandler),
    ('/disconnect', DisconnectDropboxHandler)
], debug=True, config=CONFIG)
