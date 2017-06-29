require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    # Authentication strategy for connecting with the Office365 API.
    class Office365 < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, 'office365'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, :site => 'https://outlook.office.com/',
                              :authorize_url => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                              :token_url => 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid { raw_info['Id'] }

      # https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later
      info do
        {
          :name => raw_info['DisplayName'],
          :email => raw_info['EmailAddress'],
          :nickname => raw_info['Alias'],
          :image => avatar_file
        }
      end

      extra do
        {
          :raw_info => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('api/v2.0/me').parsed
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

      def avatar_file
        photo = access_token.get("https://outlook.office.com/api/v2.0/me/photo/$value")
        ext   = photo.content_type.sub("image/", "") # "image/jpeg" => "jpeg"

        Tempfile.new(["avatar", ".#{ext}"]).tap do |file|
          file.binmode
          file.write(photo.body)
          file.rewind
        end

      rescue ::OAuth2::Error => e
        if e.response.status == 404 # User has no avatar...
          return nil
        elsif e.code["code"] == "GetUserPhoto" && e.code["message"].match("not supported")
          nil
        else
          raise
        end
      end
    end
  end
end
