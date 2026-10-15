# frozen_string_literal: true

require 'bcrypt'
require 'jwt'

module Toolshed
  # Issues and reads the bearer tokens of a member session.
  class TokenService
    ALGORITHM = 'HS256'

    def initialize(repositories)
      @repositories = repositories
    end

    def issue(member)
      now = Time.now.to_i
      JWT.encode({
                   sub: member['id'].to_s,
                   email: member['email'],
                   role: member['role'],
                   iat: now,
                   exp: now + ttl
                 }, signing_key, ALGORITHM)
    end

    def authenticate(email, password)
      member = @repositories.member_by_email(email)
      return nil if member.nil?
      return nil unless BCrypt::Password.new(member['password']) == password

      member
    rescue BCrypt::Errors::InvalidHash
      nil
    end

    def from_header(authorization)
      return nil unless authorization.to_s.start_with?('Bearer ')

      claims, = JWT.decode(authorization[7..], signing_key, true, algorithm: ALGORITHM)
      @repositories.member(claims['sub'].to_i)
    rescue JWT::DecodeError
      nil
    end

    private

    def signing_key
      key = ENV.fetch('TOOLSHED_TOKEN_KEY', nil)
      raise 'TOOLSHED_TOKEN_KEY is not set' if key.nil? || key.empty?

      key
    end

    def ttl
      value = ENV.fetch('TOOLSHED_TOKEN_TTL', '3600').to_i
      value.positive? ? value : 3600
    end
  end
end
