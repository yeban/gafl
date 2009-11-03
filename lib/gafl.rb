# MAKe sure we're running inside Merb
if defined?(Merb::Plugins)

  # Merb gives you a Merb::Plugins.config hash...feel free to put your stuff in your piece of it
  Merb::Plugins.config[:gafl] = {
    :domain => 'site-xrds?hd=intellecap.net',
    :identity_url => 'https://www.google.com/accounts/o8/id'
  }

  path = "#{File.expand_path(File.dirname(__FILE__))}/gafl/strategy.rb"
  Merb::Authentication.register(:gafl, path)
  
  Merb::BootLoader.before_app_loads do
  end
  
  Merb::BootLoader.after_app_loads do
    # code that can be required after the application loads
  end
  
  Merb::Plugins.add_rakefiles "gafl/merbtasks"

end

