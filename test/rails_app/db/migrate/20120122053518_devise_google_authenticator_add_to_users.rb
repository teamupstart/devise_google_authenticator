class DeviseGoogleAuthenticatorAddToUsers < ActiveRecord::Migration
  def self.up
    change_table :users do |t|
      t.string  :gauth_secret
      t.boolean  :gauth_enabled, default: false
      t.string  :gauth_tmp
      t.datetime  :gauth_tmp_datetime
    end

  end
  
  def self.down
    change_table :users do |t|
      t.remove :gauth_secret, :gauth_enabled, :gauth_tmp, :gauth_tmp_datetime
    end
  end
end
