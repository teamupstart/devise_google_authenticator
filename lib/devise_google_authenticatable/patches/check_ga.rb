module DeviseGoogleAuthenticator::Patches
  # patch Sessions controller to check that the OTP is accurate
  module CheckGA
    extend ActiveSupport::Concern

    included do
      alias_method :create_original, :create

      define_method :create do
        resource = warden.authenticate!(:scope => resource_name, :recall => "#{controller_path}#new")

        # Resource has G2FA enabled
        if resource.respond_to?(:get_qr) && resource.gauth_enabled?
          tmpid = resource.assign_tmp #assign a temporary key and fetch it
          warden.logout #log the user out

          #we head back into the checkga controller with the temporary id
          respond_with resource, :location => { :controller => 'checkga', :action => 'show', :id => tmpid}

        else # not enabled
          set_flash_message(:notice, :signed_in) if is_navigational_format?
          sign_in(resource_name, resource)
          respond_with resource, :location => after_sign_in_path_for(resource)
        end
      end
    end
  end
end