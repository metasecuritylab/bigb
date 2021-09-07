require 'dashing'

config_file = File.dirname(File.expand_path(__FILE__)) + '/config.yml'
config = YAML::load(File.open(config_file))

configure do
  set :auth_token, config["API_KEY"]
  set :template_languages, %i[html erb]
  set :show_exceptions, false

  helpers do
    def protected!
    end
  end
end

map Sinatra::Application.assets_prefix do
  run Sinatra::Application.sprockets
end

run Sinatra::Application
