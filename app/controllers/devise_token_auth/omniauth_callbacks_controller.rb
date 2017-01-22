module DeviseTokenAuth
  class OmniauthCallbacksController < DeviseTokenAuth::ApplicationController
  # DeviseTokenAuth::ApplicationController
  # 
  # layout :layout_by_resource
  # prepend_before_filter :require_no_authentication, :only => [:create ]
  include DeviseTokenAuth::Concerns::SetUserByToken
  include Devise
  require 'open-uri'
  require 'open_uri_redirections'
  # skip_before_filter :set_user_by_token
  # skip_after_filter :update_auth_header

    # not support multiple models, so we must resort to this terrible hack.
    def redirect_callbacks
      # derive target redirect route from 'resource_class' param, which was set
      # before authentication.
      devise_mapping = request.env['omniauth.params']['resource_class'].underscore.to_sym
      redirect_route = "/#{Devise.mappings[devise_mapping].as_json["path"]}/#{params[:provider]}/callback"

      # preserve omniauth info for success route
      session['dta.omniauth.auth'] = request.env['omniauth.auth']
      session['dta.omniauth.params'] = request.env['omniauth.params']

      redirect_to redirect_route
    end

    def process_uri(uri)
      
      open(uri, :allow_redirections => :safe) do |r|
        r.base_uri.to_s
      end
    end

    def facebook_access_token
      #user_type = params[:user_type]

      request.env['omniauth.auth']
      users = resource_class.where({
        uid:      auth_hash['uid'],
        provider: auth_hash['provider']
      })
       @resource = users.first_or_initialize

      

      # create token info
      @client_id = SecureRandom.urlsafe_base64(nil, false)
      @token     = SecureRandom.urlsafe_base64(nil, false) 
      @expiry    = (Time.now + DeviseTokenAuth.token_lifespan).to_i

      # @auth_origin_url = generate_url(omniauth_params['auth_origin_url'], {
      #   token:     @token,
      #   client_id: @client_id,
      #   uid:       @resource.uid,
      #   expiry:    @expiry
      # })

      # set crazy password for new oauth users. this is only used to prevent
      # access via email sign-in.
      unless @resource.id
        p = SecureRandom.urlsafe_base64(nil, false)
        @resource.password = p
        @resource.password_confirmation = p
      end

      @resource.tokens[@client_id] = {
        token: BCrypt::Password.create(@token),
        expiry: @expiry
      }

      # sync user info with provider, update/generate auth token
      assign_provider_attrs(@resource, auth_hash)

      # assign any additional (whitelisted) attributes
      extra_params = whitelisted_params
      @resource.assign_attributes(extra_params) if extra_params

      # facebook_image_url = process_uri(auth_hash['info']['image'])
      # @resource.profile_image = facebook_image_url
      extra_params = whitelisted_params
      @resource.assign_attributes(extra_params) if extra_params
      facebook_image_url = process_uri(auth_hash['info']['image'])
      logger.debug "facebook Image: #{facebook_image_url}"
      @resource.profile_image = facebook_image_url
      
      if resource_class.devise_modules.include?(:confirmable)
        # don't send confirmation email!!!
        @resource.skip_confirmation!
      end

      sign_in(:user, @resource, store: false, bypass: false)

      @resource.save!

      render json: {
          data: @resource.as_json()
        }
    end

    def omniauth_success
      # find or create user by provider and provider uid
      hash = request.params.slice("access_token", "expires_at", "expires_in", "refresh_token")
      # logger.debug "callback hash: #{hash}"
      # logger.debug "omniauth_params: #{request.env.inspect}"
      # logger.debug "uid: #{auth_hash.inspect}"
      logger.debug "request.env['omniauth.auth']: #{request.env['omniauth.auth']}"
      @resource = resource_class.where({
        uid:      auth_hash['uid'],
        provider: auth_hash['provider']
      }).first_or_initialize

      # create token info
      @client_id = SecureRandom.urlsafe_base64(nil, false)
      @token     = SecureRandom.urlsafe_base64(nil, false)
      @expiry    = (Time.now + DeviseTokenAuth.token_lifespan).to_i

      @auth_origin_url = generate_url(omniauth_params['auth_origin_url'], {
        token:     @token,
        client_id: @client_id,
        uid:       @resource.uid,
        expiry:    @expiry
      })

      # set crazy password for new oauth users. this is only used to prevent
      # access via email sign-in.
      unless @resource.id
        p = SecureRandom.urlsafe_base64(nil, false)
        @resource.password = p
        @resource.password_confirmation = p
      end

      @resource.tokens[@client_id] = {
        token: BCrypt::Password.create(@token),
        expiry: @expiry
      }

      # sync user info with provider, update/generate auth token
      assign_provider_attrs(@resource, auth_hash)

      # assign any additional (whitelisted) attributes
      extra_params = whitelisted_params
      @resource.assign_attributes(extra_params) if extra_params
      facebook_image_url = process_uri(auth_hash['info']['image'])
      @resource.profile_image = facebook_image_url
      if resource_class.devise_modules.include?(:confirmable)
        # don't send confirmation email!!!
        @resource.skip_confirmation!
      end

      sign_in(:user, @resource, store: false, bypass: false)

      @resource.save!

      # render user info to javascript postMessage communication window
      render :layout => "layouts/omniauth_response", :template => "devise_token_auth/omniauth_success"
    end


    # break out provider attribute assignment for easy method extension
    def assign_provider_attrs(user, auth_hash)
      logger.debug "assign_provider_attrs is called"
      user.assign_attributes({
        # nickname: auth_hash['info']['nickname'],
        name:     auth_hash['info']['name'],
        # profile_image:    auth_hash['info']['image'],
        email:    auth_hash['info']['email']
      })
    end


    def omniauth_failure
      logger.debug "omniauth_failure is called"
      @error = params[:message]
      # render :layout => "layouts/omniauth_response", :template => "devise_token_auth/omniauth_failure"
      render json: {
          success: 'failed',
          error: @error
        }
    end

    def failure
       logger.debug "failure is called"
       @error = params[:message]
       render json: {
          success: 'failed',
          error: 'omniauth_failure'
        }, status: 401
       # render :layout => "layouts/omniauth_response", :template => "devise_token_auth/omniauth_failure"
    end


    # derive allowed params from the standard devise parameter sanitizer
    def whitelisted_params
      logger.debug "whitelisted_params is called"
      whitelist = devise_parameter_sanitizer.for(:sign_up)

      whitelist.inject({}){|coll, key|
        param = omniauth_params[key.to_s]
        if param
          coll[key] = param
        end
        coll
      }
    end

    # pull resource class from omniauth return
    def resource_class
      # logger.debug "resource_class is called"
      # if omniauth_params
      #   logger.debug "omniauth_params is not empty"
      #   omniauth_params['resource_class'].constantize
      # end
      "User".constantize
    end

    def resource_name
      resource_class
    end

    # this will be determined differently depending on the action that calls
    # it. redirect_callbacks is called upon returning from successful omniauth
    # authentication, and the target params live in an omniauth-specific
    # request.env variable. this variable is then persisted thru the redirect
    # using our own dta.omniauth.params session var. the omniauth_success
    # method will access that session var and then destroy it immediately
    # after use.
    def omniauth_params
      if request.env['omniauth.params']
        request.env['omniauth.params']
      else
        @_omniauth_params ||= session.delete('dta.omniauth.params')
        @_omniauth_params
      end
    end

    # this sesison value is set by the redirect_callbacks method. its purpose
    # is to persist the omniauth auth hash value thru a redirect. the value
    # must be destroyed immediatly after it is accessed by omniauth_success
    def auth_hash
      logger.debug "auth_hash is called"
      @_auth_hash ||= session.delete('dta.omniauth.auth')
      @_auth_hash
      request.env['omniauth.auth']
    end

    # ensure that this controller responds to :devise_controller? conditionals.
    # this is used primarily for access to the parameter sanitizers.
    def assert_is_devise_resource!
      logger.debug "assert_is_devise_resource is called"
      true
    end

    # necessary for access to devise_parameter_sanitizers
    def devise_mapping
      logger.debug "devise_mapping is called"
      if omniauth_params
        Devise.mappings[omniauth_params['resource_class'].underscore.to_sym]
      else
        request.env['devise.mapping']
      end
    end

    def generate_url(url, params = {})
      auth_url = url

      # ensure that hash-bang is present BEFORE querystring for angularjs
      unless url.match(/#/)
        auth_url += '#'
      end

      # add query AFTER hash-bang
      auth_url += "?#{params.to_query}"

      return auth_url
    end

end
end
