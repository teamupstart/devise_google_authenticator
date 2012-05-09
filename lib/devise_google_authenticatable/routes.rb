module ActionDispatch::Routing # :nodoc:
  class Mapper # :nodoc:
    protected

    # Set up Google authentication routes
    def devise_google_auth(mapping, controllers)
      # resource :displayqr,
      #   :only => [:show, :update],
      #   :path => mapping.path_names[:displayqr],
      #   :controller => controllers[:displayqr]

      resource :checkga,
        :only => [:show, :update],
        :path => mapping.path_names[:checkga],
        :controller => controllers[:checkga]
    end
  end
end