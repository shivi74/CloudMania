#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import base64
import urllib

from google.appengine.api import users
from google.appengine.ext import ndb

import jinja2
import webapp2

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class MainPage(webapp2.RequestHandler):

    def get(self):
        template_values = {
            'firstname': 'Shivani',
            'lastname': 'Sharma'
        }

        template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render(template_values))

class NextPage(webapp2.RequestHandler):

    def get(self):
        template_values = {
            'firstname': 'Love',
            'lastname': 'Sharma'
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
