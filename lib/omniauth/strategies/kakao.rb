require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Kakao < OmniAuth::Strategies::OAuth2
      DEFAULT_REDIRECT_PATH = "/oauth"

      option :name, 'kakao'

      option :client_options, {
        :site => 'https://kauth.kakao.com',
        :authorize_path => '/oauth/authorize',
        :token_url => '/oauth/token',
      }
      
      uid { raw_info['id'].to_s }

      info do
        {
          'name' => raw_properties['nickname'],
          'image' => raw_properties['thumbnail_image'],
        }
      end

      extra do
        {'properties' => raw_properties}
      end

      def initialize(app, *args, &block)
        super
        options[:callback_path] = options[:redirect_path] || DEFAULT_REDIRECT_PATH
      end

      def callback_phase
        previous_callback_path = options.delete(:callback_path)
        @env["PATH_INFO"] = callback_path
        options[:callback_path] = previous_callback_path
        super
      end
      
      # callback_uri와 관련해서 redirect_uri_mismatch 문제가 나오던것을 path match를 통해서 해결합니다.
      # 해당 문제는 https://devtalk.kakao.com/t/rest-api-omniauth/19207 에서 나오는 문제를 해결합니다.
      # NOTE If we're using code from the signed request then FB sets the redirect_uri to '' during the authorize
      #      phase and it must match during the access_token phase:
      #      https://github.com/facebook/facebook-php-sdk/blob/master/src/base_facebook.php#L477
      def callback_url
        if @authorization_code_from_signed_request_in_cookie
          ''
        else
          # callback url ignorance issue from https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
          options[:callback_url] || (full_host + script_name + callback_path)
        end
      end
       
      def mock_call!(*)
        options.delete(:callback_path)
        super
      end

    private
      def raw_info
        @raw_info ||= access_token.get('https://kapi.kakao.com/v2/user/me', {}).parsed || {}
      end

      def raw_properties
        @raw_properties ||= raw_info['properties']
      end
    end
  end
end

OmniAuth.config.add_camelization 'kakao', 'Kakao'
