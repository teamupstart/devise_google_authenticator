module DeviseGoogleAuthenticator::Patches
  # patch Sessions controller to check that the OTP is accurate
  module CheckGA
    extend ActiveSupport::Concern

    included do
      alias_method :create_original, :create

      define_method :create do
        resource = warden.authenticate!(:scope => resource_name, :recall => "#{controller_path}#new")

        # Resource has G2FA enabled
        if resource.respond_to?(:get_qr) && resource.gauth_enabled == 1
          tmpid = resource.assign_tmp # assign a temporary key and fetch it
          warden.logout # log the user out

          # redirect to GA controller to check token
          scope = Devise::Mapping.find_scope!(resource)
          checkga_url = send("#{scope}_checkga_url", :id => tmpid)
          respond_with resource, :location => checkga_url

        else # G2FA not enabled - sign in normally
          set_flash_message(:notice, :signed_in) if is_navigational_format?
          sign_in(resource_name, resource)
          respond_with resource, :location => after_sign_in_path_for(resource)
        end
      end
    end
  end
end