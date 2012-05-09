require 'active_support/concern'

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
          # Assign a temporary key and fetch it
          tmpid = resource.assign_gauth_tmp

          # Log the user out
          warden.logout

          # Redirect to GA controller to request the token
          checkga_url = send("#{scope}_checkga_url", :id => tmpid)
          respond_with resource, :location => checkga_url

        # G2FA not enabled - sign in normally
        else
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
      cookies.signed["#{resource.class.name}-#{resource.id}"]
    end
  end
end