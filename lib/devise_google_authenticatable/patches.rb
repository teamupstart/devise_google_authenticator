module DeviseGoogleAuthenticator
  module Patches
    # autoload :DisplayQR, 'devise_google_authenticatable/patches/display_qr'
    autoload :CheckGA, 'devise_google_authenticatable/patches/check_ga'

    class << self
      def apply
        # Don't automatically redirect to QR code after signup
        # Devise::RegistrationsController.send(:include, Patches::DisplayQR)
        Devise::SessionsController.send(:include, Patches::CheckGA)
      end
    end
  end
end
