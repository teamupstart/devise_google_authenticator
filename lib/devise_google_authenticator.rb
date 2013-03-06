require 'active_record/connection_adapters/abstract/schema_definitions'
require 'active_support/core_ext/integer'
require 'active_support/core_ext/string'
require 'active_support/ordered_hash'
require 'active_support/concern'
require 'devise'

module Devise # :nodoc:
	mattr_accessor :ga_timeout
	@@ga_timeout = 3.minutes

	mattr_accessor :ga_timedrift
	@@ga_timedrift = 3

  mattr_accessor :remember_gauth_for
  @@remember_gauth_for = 30.days
end

module DeviseGoogleAuthenticator # :nodoc:
  autoload :Schema, 'devise_google_authenticatable/schema'
  autoload :Patches, 'devise_google_authenticatable/patches'
end

require 'devise_google_authenticatable/routes'
require 'devise_google_authenticatable/rails'
require 'devise_google_authenticatable/orm/active_record'
require 'devise_google_authenticatable/controllers/helpers'

ActionView::Base.send :include, DeviseGoogleAuthenticator::Controllers::Helpers

Devise.add_module :google_authenticatable,
  :controller => :google_authenticatable,
  :model => 'devise_google_authenticatable/models/google_authenticatable',
  :route => :google_auth