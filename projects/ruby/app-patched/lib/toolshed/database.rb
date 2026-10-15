# frozen_string_literal: true

require 'bcrypt'
require 'fileutils'
require 'sqlite3'

module Toolshed
  # SQLite access layer and the initial dataset of the workshop.
  class Database
    DDL = <<~SQL
      CREATE TABLE IF NOT EXISTS members (
          id        INTEGER PRIMARY KEY AUTOINCREMENT,
          email     TEXT UNIQUE NOT NULL,
          full_name TEXT NOT NULL,
          password  TEXT NOT NULL,
          role      TEXT NOT NULL DEFAULT 'member'
      );
      CREATE TABLE IF NOT EXISTS tools (
          id          INTEGER PRIMARY KEY AUTOINCREMENT,
          name        TEXT NOT NULL,
          category    TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          daily_rate  REAL NOT NULL DEFAULT 0,
          available   INTEGER NOT NULL DEFAULT 1
      );
      CREATE TABLE IF NOT EXISTS rentals (
          id        INTEGER PRIMARY KEY AUTOINCREMENT,
          member_id INTEGER NOT NULL REFERENCES members(id),
          tool_id   INTEGER NOT NULL REFERENCES tools(id),
          taken_on  TEXT NOT NULL,
          due_on    TEXT NOT NULL,
          notes     TEXT NOT NULL DEFAULT '',
          returned  INTEGER NOT NULL DEFAULT 0
      );
    SQL

    SEED_TOOLS = [
      ['Circular saw', 'cutting', '190 mm blade, 1400 W', 12.5],
      ['Impact driver', 'drilling', '18 V, two batteries', 8.0],
      ['Mitre saw', 'cutting', 'Sliding, 255 mm', 18.0],
      ['Heat gun', 'finishing', '2000 W, variable', 5.5],
      ['Mortar mixer', 'masonry', '1600 W, 140 mm paddle', 15.0]
    ].freeze

    SEED_MEMBERS = [
      ['ada@toolshed.example', 'Ada Mallory', 'workshop-keeper', 'staff'],
      ['jun@toolshed.example', 'Jun Watanabe', 'sawdust-season', 'member'],
      ['pierre@toolshed.example', 'Pierre Lefranc', 'bench-grinder', 'member']
    ].freeze

    attr_reader :db

    def initialize(file)
      FileUtils.mkdir_p(File.dirname(file))
      @db = SQLite3::Database.new(file)
      @db.results_as_hash = true
      @db.execute_batch(DDL)
      seed
    end

    private

    def seed
      return if @db.get_first_value('SELECT COUNT(*) FROM tools').to_i.positive?

      SEED_TOOLS.each do |row|
        @db.execute(
          'INSERT INTO tools (name, category, description, daily_rate) VALUES (?, ?, ?, ?)', row
        )
      end
      SEED_MEMBERS.each do |email, name, password, role|
        @db.execute(
          'INSERT INTO members (email, full_name, password, role) VALUES (?, ?, ?, ?)',
          [email, name, BCrypt::Password.create(password), role]
        )
      end
    end
  end
end
