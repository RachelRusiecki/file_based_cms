require "pry"
require "sinatra"
require "sinatra/reloader"
require "tilt/erubis"
require "redcarpet"
require "yaml"
require "bcrypt"

configure do
  enable :sessions
  set :session_secret, SecureRandom.hex(32)
end

# Render HTML
def render_markdown(text)
  markdown = Redcarpet::Markdown.new(Redcarpet::Render::HTML)
  markdown.render(text)
end

# Determine Content Type
def load_file_content(path)
  content = File.read(path)
  case File.extname(path)
  when '.txt'
    headers['Content-Type'] = 'text/plain'
    content
  when '.md'
    erb render_markdown(content)
  end
end

# Determine file path based on environment
def data_path
  if ENV['RACK_ENV'] == 'test'
    File.expand_path('../test/data', __FILE__)
  else
    File.expand_path('../data', __FILE__)
  end
end

# Determine YAML file path based on environment
def load_user_credentials
  credentials_path = if ENV['RACK_ENV'] == 'test'
    File.expand_path('../test/users.yml', __FILE__)
  else
    File.expand_path('../users.yml', __FILE__)
  end
  YAML.load_file(credentials_path)
end

# Determine if user is signed in
def user_signed_in?
  session.key?(:username)
end

# Store sign in message
def require_signed_in_user
  unless user_signed_in?
    session[:message] = 'You must be signed in to do that.'
    redirect '/'
  end
end

# Check for valid credentials
def valid_credentials?(username, password)
  credentials = load_user_credentials
  if credentials.key?(username)
    bcrypt_password = BCrypt::Password.new(credentials[username])
    bcrypt_password == password
  else
    false
  end
end

# Display file links
get "/" do
  pattern = File.join(data_path, '*')
  @files = Dir.glob(pattern).map { |path| File.basename(path) }
  erb :index
end

# Display new file form
get "/new" do
  require_signed_in_user
  erb :new
end

# Display index
get "/:filename" do
  file_path = File.join(data_path, params[:filename])
  if File.exist?(file_path)
    load_file_content(file_path)
  else
    session[:message] = "#{params[:filename]} does not exist."
    redirect "/"
  end
end

# Edit file display
get "/:filename/edit" do
  require_signed_in_user
  file_path = File.join(data_path, params[:filename])
  @filename = params[:filename]
  @content = File.read(file_path)
  erb :edit
end

# Add new file
post "/create" do
  require_signed_in_user
  filename = params[:filename].to_s
  if filename.strip.size == 0
    session[:message] = 'A name is required.'
    status 422
    erb :new
  elsif !['.txt', '.md'].include?(File.extname(filename))
    session[:message] = 'You must specify the type of file.'
    status 422
    erb :new
  else
    file_path = File.join(data_path, filename)
    File.write(file_path, '')
    session[:message] = "#{params[:filename]} has been created."
    redirect '/'
  end
end

# Edit file
post "/:filename" do
  require_signed_in_user
  file_path = File.join(data_path, params[:filename])
  File.write(file_path, params[:content])
  session[:message] = "#{params[:filename]} has been updated."
  redirect '/'
end

# Delete file
post "/:filename/delete" do
  require_signed_in_user
  file_path = File.join(data_path, params[:filename])
  File.delete(file_path)
  session[:message] = "#{params[:filename]} has been deleted."
  redirect '/'
end

# Display sign in page
get "/users/signin" do
  erb :signin
end

# Sign in
post "/users/signin" do
  username = params[:username]
  if valid_credentials?(username, params[:password])
    session[:message] = 'Welcome!'
    session[:username] = username
    redirect '/'
  else
    session[:message] = 'Invalid credentials'
    status 422
    erb :signin
  end
end

# Sign out
post "/users/signout" do
  session.delete(:username)
  session[:message] = 'You have been signed out.'
  redirect '/'
end
