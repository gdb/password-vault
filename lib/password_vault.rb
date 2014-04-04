require 'uri'

class PasswordVault
  BIND = 'localhost'
  PORT = 7331
  VAULT = '/pay/password-vault'

  # configure this for the server daemon (not used by clients)
  @@to_email = nil
  def self.TO_EMAIL
    return @@to_email? @@to_email : raise("Insert email address here")
  end

  # configure this for the server daemon (not used by clients)
  @@from_email = "foo bar"
  def self.FROM_EMAIL
    if @@from_email then
      return "#{`hostname`.strip} vault <#{@@from_email}>"
    else
      raise("Insert email address here")
    end
  end

  def self.name_ok?(password_name)
    # Exclude things with funky characters, such as emacs tilde files.  Also
    # exclude dotfiles including ., ..
    password_name.split('/').each do |piece|
      return false unless piece !~ /^\./ and /^[a-zA-Z0-9.-]+$/ =~ piece
    end
  end

  def self.single_escape(txt)
    txt = txt.dup.force_encoding("BINARY") if txt.respond_to? :force_encoding
    URI.escape(txt, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
  end

  # It appears that sinatra first unescapes and then splits on slashes for routing
  def self.escape(txt)
    single_escape(single_escape(txt))
  end

  def self.unescape(txt)
    URI.unescape(txt)
  end
end
