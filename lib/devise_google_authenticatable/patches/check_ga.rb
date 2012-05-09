require 'active_support/concern'
require 'digest/sha2'

# Patch Sessions controller to require a token, if applicable.
module DeviseGoogleAuthenticator::Patches
  module CheckGA
    extend ActiveSupport::Concern

    included do
      alias_method :create_original, :create

      define_method :create do
        resource = warden.authenticate!(
          :scope => resource_name,
          :recall => "#{controller_path}#new"
        )

        scope = Devise::Mapping.find_scope!(resource)

        # Resource has G2FA enabled
        if gauth_required?(resource)
          # Log the user out
          warden.logout

          # Assign a temporary key and fetch it
          session[:gauth_tmp] = resource.assign_gauth_tmp

          ap "SESSION"
          ap session.inspect

          # Redirect to GA controller to request the token
          respond_with resource, :location => send("#{scope}_checkga_url")

        # G2FA not enabled - sign in normally
        else
          # clear any previous temporary keys
          session[:gauth_tmp] = nil

          set_flash_message(:notice, :signed_in) if is_navigational_format?
          sign_in(resource_name, resource)
          respond_with resource, :location => after_sign_in_path_for(resource)
        end
      end
    end

    private

    def gauth_required?(resource)
      resource.respond_to?(:get_qr) &&
      resource.needs_gauth? &&
      !gauth_remembered?(resource)
    end

    def gauth_remembered?(resource)
      remember_key = Digest::SHA2.new << "#{resource_name}-#{resource.id}"
      remember_value = Digest::SHA2.new << resource.gauth_secret

      cookies.signed[remember_key.to_s] == remember_value.to_s
    end
  end
end