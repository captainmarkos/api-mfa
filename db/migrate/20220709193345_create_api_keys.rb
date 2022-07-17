class CreateApiKeys < ActiveRecord::Migration[7.0]
  def change
    create_table :api_keys do |t|
      t.references :bearer, polymorphic: true, index: true
      t.string :token_digest, null: false

      t.timestamps
    end

    add_index :api_keys, :token_digest, unique: true
  end
end
