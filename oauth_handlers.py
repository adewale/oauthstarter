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
from google.appengine.api import xmpp
from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp.util import login_required

import apiclient.ext.appengine
import apiclient.oauth
import apiclient.discovery
import buzz_gae_client
import httplib2
import logging
import os
import settings
import simple_buzz_wrapper

class UserToken(db.Model):
# The user_id is the key_name so we don't have to make it an explicit property
  request_token_string = db.StringProperty()
  access_token_string = db.StringProperty()
  email_address = db.StringProperty()

  def get_request_token(self):
    "Returns request token as a dictionary of tokens including oauth_token, oauth_token_secret and oauth_callback_confirmed."
    return eval(self.request_token_string)

  def set_access_token(self, access_token):
    access_token_string = repr(access_token)
    self.access_token_string = access_token_string

  def get_access_token(self):
    "Returns access token as a dictionary of tokens including consumer_key, consumer_secret, oauth_token and oauth_token_secret"
    return eval(self.access_token_string)

  @staticmethod
  def create_user_token(request_token):
    user = users.get_current_user()
    user_id = user.user_id()
    request_token_string = repr(request_token)

    # TODO(ade) Support users who sign in to AppEngine with a federated identity aka OpenId
    email = user.email().lower()

    logging.info('Creating user token: key_name: %s request_token_string: %s email_address: %s' % (
    user_id, request_token_string, email))

    return UserToken(key_name=user_id, request_token_string=request_token_string, access_token_string='',
                     email_address=email)

  @staticmethod
  def get_current_user_token():
    user = users.get_current_user()
    user_token = UserToken.get_by_key_name(user.user_id())
    return user_token

  @staticmethod
  def access_token_exists():
    user = users.get_current_user()
    user_token = UserToken.get_by_key_name(user.user_id())
    logging.info('user_token: %s' % user_token)
    return user_token and user_token.access_token_string

  @staticmethod
  def find_by_email_address(email_address):
    user_tokens = UserToken.gql('WHERE email_address = :1', email_address).fetch(1)
    if user_tokens:
      return user_tokens[0] # The result of the query is a list
    else:
      return None

class DanceStartingHandler(webapp.RequestHandler):
  @login_required
  def get(self):
    logging.info('Request body %s' % self.request.body)
    user = users.get_current_user()
    logging.debug('Started OAuth dance for: %s' % user.email())

    template_values = {}
    if UserToken.access_token_exists():
      template_values['access_token_exists'] = 'true'
    else:
    # Generate the request token
      client = buzz_gae_client.BuzzGaeClient(settings.CONSUMER_KEY, settings.CONSUMER_SECRET)
      request_token = client.get_request_token(self.request.host_url + '/finish_dance')
      logging.info('Request token: %s' % request_token)

      # Create the request token and associate it with the current user
      user_token = UserToken.create_user_token(request_token)
      UserToken.put(user_token)

      authorisation_url = client.generate_authorisation_url(request_token)
      logging.info('Authorisation URL is: %s' % authorisation_url)
      template_values['destination'] = authorisation_url

    path = os.path.join(os.path.dirname(__file__), 'start_dance.html')
    self.response.out.write(template.render(path, template_values))


class TokenDeletionHandler(webapp.RequestHandler):
  def post(self):
    user_token = UserToken.get_current_user_token()
    UserToken.delete(user_token)
    self.redirect(settings.FRONT_PAGE_HANDLER_URL)


class DanceFinishingHandler(webapp.RequestHandler):
  def get(self):
    logging.info("Request body %s" % self.request.body)
    user = users.get_current_user()
    logging.debug('Finished OAuth dance for: %s' % user.email())

    f = Flow.get_by_key_name(user.user_id())
    if f:
      credentials = f.flow.step2_exchange(self.request.params)
      c = Credentials(key_name=user.user_id(), credentials=credentials)
      c.put()
      f.delete()

    self.redirect(settings.PROFILE_HANDLER_URL)

def make_wrapper(email_address):
  user_token = UserToken.find_by_email_address(email_address)
  if user_token:
    oauth_params_dict = user_token.get_access_token()
    return simple_buzz_wrapper.SimpleBuzzWrapper(api_key=settings.API_KEY, consumer_key=oauth_params_dict['consumer_key'],
      consumer_secret=oauth_params_dict['consumer_secret'], oauth_token=oauth_params_dict['oauth_token'], 
      oauth_token_secret=oauth_params_dict['oauth_token_secret'])
  else:
    return simple_buzz_wrapper.SimpleBuzzWrapper(api_key=settings.API_KEY)


class Flow(db.Model):
  flow = apiclient.ext.appengine.FlowThreeLeggedProperty()


class Credentials(db.Model):
  credentials = apiclient.ext.appengine.OAuthCredentialsProperty()

def oauth_required(handler_method):
  """A decorator to require that a user has gone through the OAuth dance before accessing a handler.
  
  To use it, decorate your get() method like this:
    @oauth_required
    def get(self):
      buzz_wrapper = oauth_handlers.build_buzz_wrapper_for_current_user()
      user_profile_data = buzz_wrapper.get_profile()
      self.response.out.write('Hello, ' + user_profile_data.displayName)
  
  We will redirect the user to the OAuth endpoint and afterwards the OAuth
  will send the user back to the DanceFinishingHandler that you have configured.
  This should only used for GET requests since any payload in a POST request
  will be lost.
  """
  def check_oauth_credentials(self, *args):
    if self.request.method != 'GET':
      raise webapp.Error('The check_login decorator can only be used for GET '
                         'requests')

    # Is this a request from the OAuth system after finishing the OAuth dance?
    if self.request.get('oauth_verifier'):
      user = users.get_current_user()
      logging.debug('Finished OAuth dance for: %s' % user.email())

      f = Flow.get_by_key_name(user.user_id())
      if f:
        credentials = f.flow.step2_exchange(self.request.params)
        c = Credentials(key_name=user.user_id(), credentials=credentials)
        c.put()
        f.delete()
      handler_method(self, *args)
      return 

    # Find out who the user is. If we don't know who you are then we can't 
    # look up your OAuth credentials.
    # TODO(ade) Look up the user's id in a cookie first then fallback to 
    # appengine login.
    user = users.get_current_user()
    if not user:
      self.redirect(users.create_login_url(self.request.uri))
      return
    
    # If we know the user then look up their OAuth credentials
    if not Credentials.get_by_key_name(user.user_id()):
      #TODO(ade) make this configurable via settings.py rather than hardcoded to Buzz
      p = apiclient.discovery.build("buzz", "v1")
      flow = apiclient.oauth.FlowThreeLegged(p.auth_discovery(),
                     consumer_key=settings.CONSUMER_KEY,
                     consumer_secret=settings.CONSUMER_SECRET,
                     user_agent='google-api-client-python-buzz-webapp/1.0',
                     domain='anonymous',
                     scope='https://www.googleapis.com/auth/buzz',
                     xoauth_displayname=settings.DISPLAY_NAME)

      # The OAuth system needs to send the user right back here so that they
      # get to the page they originally intended to visit.
      oauth_return_url = self.request.uri
      authorize_url = flow.step1_get_authorize_url(oauth_return_url)
      
      f = Flow(key_name=user.user_id(), flow=flow)
      f.put()
      
      self.redirect(authorize_url)
      return
    handler_method(self, *args)
  return check_oauth_credentials


def build_buzz_wrapper_for_current_user():
  user = users.get_current_user()
  credentials = Credentials.get_by_key_name(user.user_id()).credentials
  #TODO(ade) This is a much simpler solution
  #http = httplib2.Http()
  #http = c.credentials.authorize(http)
  return simple_buzz_wrapper.SimpleBuzzWrapper(api_key=settings.API_KEY, 
                                              oauth_token=credentials.token.key, 
                                              oauth_token_secret=credentials.token.secret,
                                              consumer_key=credentials.consumer.key,
                                              consumer_secret=credentials.consumer.secret)
  
  
