# frozen_string_literal: true

module Toolshed
  # Read and write access to the three tables of the workshop.
  class Repositories
    def initialize(db)
      @db = db
    end

    def tools_ordered_by(column)
      @db.execute("SELECT * FROM tools ORDER BY #{column}").map { |row| cast_tool(row) }
    end

    def top_tools(limit)
      @db.execute('SELECT * FROM tools ORDER BY name LIMIT ?', [limit]).map { |row| cast_tool(row) }
    end

    def search_tools(term)
      like = "%#{term}%"
      @db.execute('SELECT * FROM tools WHERE name LIKE ? OR description LIKE ?', [like, like])
         .map { |row| cast_tool(row) }
    end

    def tool(id)
      row = @db.execute('SELECT * FROM tools WHERE id = ?', [id]).first
      row && cast_tool(row)
    end

    def member_by_email(email)
      @db.execute('SELECT * FROM members WHERE email = ?', [email]).first
    end

    def member(id)
      @db.execute('SELECT * FROM members WHERE id = ?', [id]).first
    end

    def rentals_of(member_id)
      @db.execute(<<~SQL, [member_id]).map { |row| cast_rental(row) }
        SELECT r.*, t.name AS tool_name FROM rentals r
        JOIN tools t ON t.id = r.tool_id
        WHERE r.member_id = ? ORDER BY r.taken_on DESC
      SQL
    end

    def rental_of(rental_id, member_id)
      row = @db.execute('SELECT * FROM rentals WHERE id = ? AND member_id = ?',
                        [rental_id, member_id]).first
      row && cast_rental(row)
    end

    def create_rental(member_id, tool_id, taken_on, due_on, notes)
      @db.execute(
        'INSERT INTO rentals (member_id, tool_id, taken_on, due_on, notes) VALUES (?, ?, ?, ?, ?)',
        [member_id, tool_id, taken_on, due_on, notes]
      )
      @db.last_insert_row_id
    end

    def set_tool_available(tool_id, available)
      @db.execute('UPDATE tools SET available = ? WHERE id = ?', [available ? 1 : 0, tool_id])
    end

    def close_rental(rental_id)
      @db.execute('UPDATE rentals SET returned = 1 WHERE id = ?', [rental_id])
    end

    private

    def cast_tool(row)
      {
        'id' => row['id'].to_i,
        'name' => row['name'],
        'category' => row['category'],
        'description' => row['description'],
        'daily_rate' => row['daily_rate'].to_f,
        'available' => row['available'].to_i != 0
      }
    end

    def cast_rental(row)
      out = {
        'id' => row['id'].to_i,
        'member_id' => row['member_id'].to_i,
        'tool_id' => row['tool_id'].to_i,
        'taken_on' => row['taken_on'],
        'due_on' => row['due_on'],
        'notes' => row['notes'],
        'returned' => row['returned'].to_i != 0
      }
      out['tool_name'] = row['tool_name'] if row.key?('tool_name')
      out
    end
  end
end
