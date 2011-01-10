# Copyright (C) 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import run_wsgi_app

import buzz_appengine
import logging
import os


class WelcomeHandler(webapp.RequestHandler):
    def get(self):
        logging.info("Request body %s" % self.request.body)
        template_values = {}
        path = os.path.join(os.path.dirname(__file__), 'welcome.html')
        self.response.out.write(template.render(path, template_values))


class ProfileViewingHandler(webapp.RequestHandler):
  @buzz_appengine.oauth_required
  def get(self):
    buzz_wrapper = buzz_appengine.build_buzz_wrapper_for_current_user()
    user_profile_data = buzz_wrapper.get_profile()

    logging.info('Showing profile for %s' % user_profile_data['displayName'])
    
    template_values = {'user_profile_data': user_profile_data}
    path = os.path.join(os.path.dirname(__file__), 'profile.html')
    self.response.out.write(template.render(path, template_values))


class TokenDeletionHandler(webapp.RequestHandler):
  def post(self):
    user = users.get_current_user()
    credentials = buzz_appengine.Credentials.get_by_key_name(user.user_id())
    credentials.delete()
    self.redirect('/')


application = webapp.WSGIApplication([
('/', WelcomeHandler),
('/delete_tokens', TokenDeletionHandler),
('/profile', ProfileViewingHandler)],
  debug = True)

def main():
	run_wsgi_app(application)

if __name__ == '__main__':
	main()
