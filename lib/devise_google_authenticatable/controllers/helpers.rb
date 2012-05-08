module DeviseGoogleAuthenticator
  module Controllers # :nodoc:
    module Helpers # :nodoc:
      def google_authenticator_qrcode(user)
        url = user.google_authenticator_qrcode_url
        image_tag(url, :alt => 'Google Authenticator QRCode')
      end
    end
  end
end