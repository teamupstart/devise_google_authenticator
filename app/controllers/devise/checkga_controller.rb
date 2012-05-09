class Devise::CheckgaController < Devise::SessionsController
  include Devise::Controllers::Helpers

  prepend_before_filter :require_no_authentication, :only => [:show, :update]

  def show
    @tmpid = params[:id]

    if @tmpid.nil?
      redirect_to :root
    else
      render :show
    end
  end

  def update
    resource = resource_class.find_by_gauth_tmp(params[resource_name]['tmpid'])

    # Redirect to root
    redirect_to :root if resource.nil?

    # Sign in using Gauth token
    if resource.validate_token(params[resource_name]['token'].to_i)
      remember_me(resource) if params[:remember_me]

      set_flash_message(:notice, :signed_in) if is_navigational_format?
      sign_in(resource_name, resource)

      respond_with resource, :location => after_sign_in_path_for(resource)

    # Display error if Gauth token authentication fails
    else
      @tmpid = params[resource_name]['tmpid']
      flash[:alert] = I18n.t('token_invalid', {:scope => 'devise'})

      render :show
    end
  end

  private

  # Set a remember me token if params[:remember_me] is not nil or false.
  def remember_me(resource)
    cookies.signed["#{resource.class.name}-#{resource.id}"] = {
      value: true,
      expires_at: Devise.remember_gauth_for.from_now
    }
  end
end