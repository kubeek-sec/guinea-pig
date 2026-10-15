# frozen_string_literal: true

require 'cgi'
require 'json'
require 'securerandom'
require 'sinatra/base'

require_relative 'database'
require_relative 'repositories'
require_relative 'token_service'

module Toolshed
  VERSION = '1.4.2'

  # Toolshed — the lending service of a neighbourhood workshop.
  class App < Sinatra::Base
    ROOT = File.expand_path('../..', __dir__)
    SORTABLE = %w[name category daily_rate].freeze
    PHOTO_TYPES = {
      'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
      'png' => 'image/png', 'webp' => 'image/webp'
    }.freeze
    DEFAULT_DAYS = 7
    MAX_PHOTO_BYTES = 8 * 1024 * 1024

    configure do
      set :environment, :production
      set :bind, '0.0.0.0'
      set :port, (ENV['PORT'] || 8000).to_i
      set :show_exceptions, false
      set :uploads, ENV['TOOLSHED_UPLOADS'] || File.join(ROOT, 'var', 'uploads')
      FileUtils.mkdir_p(settings.uploads)
      database = Database.new(ENV['TOOLSHED_DB'] || File.join(ROOT, 'var', 'toolshed.db'))
      set :repositories, Repositories.new(database.db)
      set :tokens, TokenService.new(settings.repositories)
    end

    helpers do
      def repo
        settings.repositories
      end

      def json_body(body, status_code = 200)
        status status_code
        content_type :json
        JSON.generate(body)
      end

      def refuse(status_code, message)
        halt status_code, { 'Content-Type' => 'application/json' },
             JSON.generate({ error: message })
      end

      def signed_in
        member = settings.tokens.from_header(request.env['HTTP_AUTHORIZATION'])
        refuse(401, 'authentication required') if member.nil?
        member
      end

      def staff
        member = signed_in
        refuse(403, 'staff only') unless member['role'] == 'staff'
        member
      end

      def public_member(member)
        {
          id: member['id'].to_i,
          email: member['email'],
          full_name: member['full_name'],
          role: member['role']
        }
      end
    end

    get '/healthz' do
      json_body({ status: 'ok', version: VERSION })
    end

    get '/openapi.yml' do
      content_type 'application/yaml'
      send_file File.join(ROOT, 'openapi.yml'), type: 'application/yaml'
    end

    get '/' do
      rows = repo.top_tools(20).map do |tool|
        format("<tr><td>%s</td><td>%s</td><td>%.2f &euro;</td><td>%s</td></tr>\n",
               CGI.escapeHTML(tool['name']), CGI.escapeHTML(tool['category']),
               tool['daily_rate'],
               tool['available'] ? 'on the rack' : '<span class="out">out</span>')
      end.join
      content_type :html
      <<~HTML
        <!doctype html>
        <html lang="en">
        <head><meta charset="utf-8"><title>Toolshed</title>
        <style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}
        table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
        .out{color:#999}</style></head>
        <body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
        <table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
        #{rows}
        </table><p><a href="/openapi.yml">API description</a></p></body></html>
      HTML
    end

    get '/api/tools' do
      sort = params['sort'] || 'name'
      refuse(400, "cannot sort on '#{sort}'") unless SORTABLE.include?(sort)
      json_body({ tools: repo.tools_ordered_by(sort) })
    end

    get '/api/tools/search' do
      term = params['q'].to_s
      json_body({ query: term, tools: repo.search_tools(term) })
    end

    get '/api/tools/:id' do
      tool = repo.tool(params['id'].to_i)
      refuse(404, 'no such tool') if tool.nil?
      json_body(tool)
    end

    post '/api/session' do
      body = JSON.parse(request.body.read) rescue {}
      member = settings.tokens.authenticate(body['email'].to_s, body['password'].to_s)
      refuse(401, 'bad credentials') if member.nil?
      json_body({ token: settings.tokens.issue(member), role: member['role'] })
    end

    get '/api/members/me' do
      json_body(public_member(signed_in))
    end

    get '/api/members/:id' do
      staff
      member = repo.member(params['id'].to_i)
      refuse(404, 'no such member') if member.nil?
      json_body(public_member(member))
    end

    get '/api/rentals' do
      member = signed_in
      json_body({ rentals: repo.rentals_of(member['id'].to_i) })
    end

    post '/api/rentals' do
      member = signed_in
      body = JSON.parse(request.body.read) rescue {}
      tool = repo.tool(body['tool_id'].to_i)
      refuse(404, 'no such tool') if tool.nil?
      refuse(409, 'already out') unless tool['available']
      days = body['days'].to_i
      days = DEFAULT_DAYS unless days.positive?
      today = Date.today
      due = today + days
      id = repo.create_rental(member['id'].to_i, tool['id'], today.to_s, due.to_s,
                              body['notes'].to_s)
      repo.set_tool_available(tool['id'], false)
      json_body({ id: id, due_on: due.to_s }, 201)
    end

    post '/api/rentals/:id/return' do
      member = signed_in
      rental = repo.rental_of(params['id'].to_i, member['id'].to_i)
      refuse(404, 'no such rental') if rental.nil?
      repo.close_rental(rental['id'])
      repo.set_tool_available(rental['tool_id'], true)
      json_body({ status: 'returned' })
    end

    post '/api/photos' do
      member = signed_in
      photo = params['photo']
      refuse(400, 'no photo') if photo.nil? || photo[:tempfile].nil?
      ext = File.extname(photo[:filename].to_s).delete_prefix('.').downcase
      refuse(400, "#{ext.empty? ? 'file' : ".#{ext}"} not accepted") unless PHOTO_TYPES.key?(ext)
      refuse(400, 'photo too large') if photo[:tempfile].size > MAX_PHOTO_BYTES
      name = "#{SecureRandom.hex(16)}.#{ext}"
      FileUtils.cp(photo[:tempfile].path, File.join(settings.uploads, name))
      json_body({ name: name, owner: member['email'] }, 201)
    end

    get '/api/photos/:name' do
      name = File.basename(params['name'].to_s)
      file = File.join(settings.uploads, name)
      refuse(404, 'no such photo') unless File.file?(file)
      ext = File.extname(name).delete_prefix('.').downcase
      headers 'X-Content-Type-Options' => 'nosniff'
      send_file file, type: PHOTO_TYPES.fetch(ext, 'application/octet-stream')
    end
  end
end
