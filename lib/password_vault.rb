require 'uri'

class PasswordVault
  TO_EMAIL = raise("Insert email address here")
  FROM_EMAIL = "#{`hostname`.strip} vault <#{raise("Insert email address here")}>"
  BIND = 'localhost'
  PORT = 7331
  VAULT = '/pay/password-vault'

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
