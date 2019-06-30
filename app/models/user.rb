class User < ApplicationRecord
	validates :username, :uniqueness => {:case_sensitive => false}
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  attr_accessor :signin

  def self.find_first_by_auth_conditions(warden_conditions)
    where(["lower(username) = :value OR lower(email) = :value", { :value => warden_conditions[:signin].downcase }]).first
end
 
end
