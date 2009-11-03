require 'openid'
require 'openid/store/filesystem'
require 'openid/extensions/ax'

module Merb::Authentication::Strategies
  class GOpenID < Merb::Authentication::Strategy

    # get the google or hosted domain's discovery url
    def self.gafl_url
      url = Merb::Plugins.config[:gafl][:base]
      (domain = Merb::Plugins.config[:gafl][:domain]) ? (url + "site-xrds?hd=#{domain}") : (url + "id")
    end

    # the part of the strategy that actually gets executed
    def run!
      if request.params[:'openid.mode']
	response = consumer.complete(request.send(:query_params), "#{request.protocol}://#{request.host}" + request.path)
	case response.status.to_s
	when 'success'
	  ax_response = ::OpenID::AX::FetchResponse.from_success_response(response)
	  result = on_success!(response, ax_response)
	  Merb.logger.info "\n\n#{result.inspect}\n\n"
	  result
	when 'failure'
	  on_failure!(response)
	when  'setup_needed'
	  on_setup_needed!(response)
	when 'cancel'
	  on_cancel!(response)
	end
      elsif openid_url = params[:openid_url]
	begin
	  openid_request = consumer.begin(openid_url)
	  add_ax_fetch_request!(openid_request)
	  redirect!(openid_request.redirect_url("#{request.protocol}://#{request.host}", openid_callback_url))
	rescue ::OpenID::OpenIDError => e
	  request.session.authentication.errors.clear!
	  request.session.authentication.errors.add(:openid, 'The OpenID verification failed')
	  nil
	end
      end
    end # run!


    # add Attribute Exchange fetch request message to the request
    # redefine to add more attributes
    def add_ax_fetch_request!(openid_request)
      ax_request = ::OpenID::AX::FetchRequest.new

      # add attributes to the fetch request message
      add_email!(ax_request)
      add_first_name!(ax_request)
      add_last_name!(ax_request)

      openid_request.add_extension(ax_request)
    end

    # next five methods add exchange attributes to the AX request
    def add_email!(ax_request)
      ax_request.add(::OpenID::AX::AttrInfo.new('http://schema.openid.net/contact/email', 'email', true))
    end

    def add_first_name!(ax_request)
      ax_request.add(::OpenID::AX::AttrInfo.new('http://axschema.org/namePerson/first', 'fname', true))
    end

    def add_last_name!(ax_request)
      ax_request.add(::OpenID::AX::AttrInfo.new('http://axschema.org/namePerson/last', 'lname', true))
    end

    def add_country!(ax_request)
      ax_request.add(::OpenID::AX::AttrInfo.new('http://axschema.org/contact/country/home', 'country', true))
    end

    def add_language!(ax_request)
      ax_request.add(::OpenID::AX::AttrInfo.new('http://axschema.org/pref/language', 'language', true))
    end

    # next five functions return attributes from the AX response
    def email(ax_response)
      ax_response.data["http://schema.openid.net/contact/email"]
    end

    def first_name(ax_response)
      ax_response.data["http://schema.openid.net/contact/email"]
    end

    def last_name(ax_response)
      ax_response.data["http://schema.openid.net/contact/email"]
    end

    def country(ax_response)
      ax_response.data["http://schema.openid.net/contact/email"]
    end

    def language(ax_response)
      ax_response.data["http://schema.openid.net/contact/email"]
    end

    # next four methods describe what to do on a success, failure... events
    # can be redefined
    def on_success!(response, ax_response)
      find_user_by_email(email(ax_response))
    end

    def on_failure!(response)
      session.authentication.errors.clear!
      session.authentication.errors.add(:openid, 'OpenID verification failed, maybe the provider is down? Or the session timed out')
      nil
    end

    def on_setup_needed!(response)
      request.session.authentication.errors.clear!
      request.session.authentication.errors.add(:openid, 'OpenID does not seem to be configured correctly')
      nil
    end

    def on_cancel!(response)
      request.session.authentication.errors.clear!
      request.session.authentication.errors.add(:openid, 'OpenID rejected our request')
      nil
    end

    def openid_callback_url
      "#{request.protocol}://#{request.host}#{Merb::Router.url(:openid)}"
    end

    # assumes an existing DataMapper User class
    # redifine if required
    def find_user_by_email(email)
      user_class.first(:email => email)
    end

    private
    def consumer
      @consumer ||= ::OpenID::Consumer.new(request.session, openid_store)
    end

    def openid_store
      ::OpenID::Store::Filesystem.new("#{Merb.root}/tmp/openid")
    end

  end # GOpenID
end # Merb::Authentication::Strategies
