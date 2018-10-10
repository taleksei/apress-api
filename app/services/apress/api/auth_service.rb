module Apress
  module Api
    class AuthService
      rattr_initialize :request

      attr_reader :client

      delegate :query_parameters, to: :request

      # Find Client by access_id, check sercret_key
      #
      # Returns boolean
      def call
        return false unless access_id

        @client = Apress::Api::Client.find_by_access_id(access_id)
        return false unless client

        return false if client.secret_token_expired?

        return true if not_check_signature?
        raise <<-EXCEPTION_MESSAGE
          md5_mismatch: #{::ApiAuth.send(:md5_mismatch?, request)}
          signatures_match: #{::ApiAuth.send(:signatures_match?, request, client.secret_token)}
          request_too_old: #{::ApiAuth.send(:request_too_old?, request)}
          canonical_string: #{::ApiAuth::Headers.new(request).canonical_string}
          secret_token: #{client.secret_token}
          access_id: #{::ApiAuth.send(:access_id, request)}
          authorization_header: #{::ApiAuth.send(:parse_auth_header, ::ApiAuth::Headers.new(request).authorization_header)}
          hmac_signature: #{::ApiAuth.send(:hmac_signature, request, client.secret_token)}
        EXCEPTION_MESSAGE
        ::ApiAuth.authentic?(request, client.secret_token)
      end

      def access_id
        @access_id ||= ApiAuth.access_id(request) || query_parameters[:access_id]
      end

      private

      def not_check_signature?
        check_signature = query_parameters[:check_signature]
        check_signature.present? && check_signature.to_i.zero? && (Rails.env.staging? || !Rails.env.production?)
      end
    end
  end
end
