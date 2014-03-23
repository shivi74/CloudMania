import cgi
import webapp2
import jinja2
import re
import os
import base64
import urllib

from google.appengine.api import users
from google.appengine.ext import db

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class User(db.Model):
  email = db.StringProperty(required = True)
  password = db.StringProperty(required = True)
  
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)
	
class MainPage(webapp2.RequestHandler):
  def get(self):
    template_values = {"email":"","email_error":"","password":"","confirm password":""}
    template = jinja_environment.get_template('index.html')
    self.response.out.write(template.render(template_values))

  def post(self):
	user_email = self.request.get('email')
	user_password = self.request.get('password')
	user_cpassword = self.request.get('confirm password')	
	geted_email_error = ""
	if (user_email and valid_email(user_email)) and (user_password and user_cpassword):
		a = User(email = user_email,
				password = base64.b64encode('user_password'))
		a.put()
	else
        geted_email_error = "e-mail is not valid!"
	template_values = {"email": user_email,"email_error": geted_email_error}
    template = jinja_environment.get_template('index.html')
    self.response.out.write(template.render(template_values))
	self.redirect('/next')

class NextPage(webapp2.RequestHandler):

    def get(self):
        template_values = {
            
        }

        template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render(template_values))

class VerifyHandler(webapp2.RequestHandler):

    def get(self, uuid):
	template = JINJA_ENVIRONMENT.get_template('index.html')
	self.response.write(template.render({'firstname': uuid, 'lastname': self.request.get('q', 'nothing')}))

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/next', NextPage),
    (r'/verify/(.*)$', VerifyHandler),
], debug=True)
