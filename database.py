from google.appengine.ext import db

Query = db.Query

class User(db.Model):
  email = db.StringProperty(required = True)
  password = db.StringProperty(required = True)
  created = db.DateTimeProperty(auto_now_add=True)
  updated = db.DateTimeProperty(auto_now=True)
  access_token = db.StringProperty()
  is_verify = db.BooleanProperty()

class Verify(db.Model):
  user = db.ReferenceProperty(User)
  uuid = db.StringProperty(required = True)

class Forgot(db.Model):
  user = db.ReferenceProperty(User)
  uuid = db.StringProperty(required = True)

class Mapping(db.Model):
  user = db.ReferenceProperty(User)
  Sitename = db.StringProperty()
  SiteID = db.StringProperty(required = True)



