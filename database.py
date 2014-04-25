from google.appengine.ext import db

Query = db.Query

class User(db.Model):
  email = db.StringProperty(required = True)
  password = db.StringProperty(required = True)
  uuid = db.StringProperty(required = True)
  created = db.DateTimeProperty(auto_now_add=True)
  updated = db.DateTimeProperty(auto_now=True)

class Verify(db.Model):
  email = db.StringProperty(required = True)
  uuid = db.StringProperty(required = True)
  is_verify = db.BooleanProperty()

class Forgot(db.Model):
  email = db.StringProperty(required = True)
  uuid = db.StringProperty(required = True)
  is_viewed = db.BooleanProperty()
  

  