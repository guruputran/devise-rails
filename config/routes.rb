Rails.application.routes.draw do
  devise_for :admins
  get 'registrations/update'
  devise_for :users, :controllers => {:registrations =>
"registrations"}
  get 'home/index'
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
 root to: "home#index"
   
end
