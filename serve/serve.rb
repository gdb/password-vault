#!/usr/bin/env ruby
require 'rubygems'

require 'fileutils'
require 'logger'
require 'optparse'
require 'pony'
require 'sinatra'

require File.join(File.dirname(__FILE__), '../lib/password_vault')
require File.join(File.dirname(__FILE__), '../lib/subprocess')

LOG = Logger.new(STDOUT)
LOG.level = Logger::WARN
DEBUG = false

class Reporter
  def report_list(alleged_requestor)
    report("[Vault] #{alleged_requestor} - password list requested",
           <<EOF
At #{Time.now}, the password daemon received a request to list available passwords.
The requestor claimed to be #{alleged_requestor}, although there's no guarantee
of authenticity.
EOF
           )
  end

  def report_recipients(password_name, alleged_requestor, opts={})
    if opts[:success]
      subject = "[Vault] #{alleged_requestor} #{password_name} - password recipients listed"
      body = 'The recipients were successfully listed.'
    else
      subject = "[Vault] #{alleged_requestor} #{password_name} - password invalidly requested"
      body = 'The password failed validation or GPG failed.'
    end
    report(subject, <<EOF
At #{Time.now}, the password daemon received a request to list the
encryption recipients of #{password_name}. The requestor claimed to be
#{alleged_requestor}, although there's no guarantee of authenticity.

#{body}
EOF
           )
  end


  def report_fetch(password_name, alleged_requestor, opts={})
    if opts[:success]
      subject = "[Vault] #{alleged_requestor} #{password_name} - password fetched"
      body = 'The password was successfully distributed.'
    else
      subject = "[Vault] #{alleged_requestor} #{password_name} - password invalidly requested"
      body = 'The password name failed validation.'
    end

    # Note that alleged_requestor is trivially forgeable.  If we care, we could
    # issue client certs to each user to make that harder.
    report(subject, <<EOF
At #{Time.now}, the password daemon received a request for #{password_name}.
The requestor claimed to be #{alleged_requestor}, although there's no guarantee
of authenticity.

#{body}
EOF
           )
  end

  def report_rm(password_name, alleged_requestor, opts={})
    if opts[:success]
      subject = "[Vault] #{alleged_requestor} #{password_name} - password deleted"
      body = 'The password was successfully deleted.'
    else
      subject = "[Vault] #{alleged_requestor} #{password_name} - password deletion failed"
      body = 'The password could not be deleted.'
    end
    report(subject, <<EOF
At #{Time.now}, the password daemon received a request to delete #{password_name}.
The requestor claimed to be #{alleged_requestor}, although there's no guarantee
of authenticity.

#{body}
EOF
           )
  end

  def report_add(password_name, alleged_requestor, opts={})
    if opts[:success]
      content = opts[:content]
      raise ArgumentError.new('No content') unless content
      if opts[:existing]
        subject = "[Vault] #{alleged_requestor} #{password_name} - password updated"
        body = "The password was successfully updated.  #{content.length} bytes were written"
      else
        subject = "[Vault] #{alleged_requestor} #{password_name} - password created"
        body = "The password was successfully created.  #{content.length} bytes were written"
      end
    else
      subject = "[Vault] #{alleged_requestor} #{password_name} - password creation failed"
      body = "Creation of the password failed."
    end
    report(subject, body)
  end

  private

  def report(subject, body)
    if DEBUG
      puts "Subject: #{subject}"
      puts "Body: #{body}"
      puts
    else
      Pony.mail(:to => PasswordVault::TO_EMAIL,
                :from => PasswordVault::FROM_EMAIL,
                :subject => subject,
                :body => body)
    end
  end
end
reporter = Reporter.new

set :bind, PasswordVault::BIND
set :port, PasswordVault::PORT
set :show_exceptions, false

def recursive_list(d)
  if File.directory?(d)
    # important that ./.. don't pass name_ok?
    Dir.entries(d).select { |f| PasswordVault.name_ok?(f) }. \
      map {|f| recursive_list(File.join(d, f))}
  else
    d
  end
end

get '/:alleged_requestor' do |alleged_requestor|
  alleged_requestor = PasswordVault.unescape(alleged_requestor)
  reporter.report_list(alleged_requestor)
  prefix = File.join(PasswordVault::VAULT, '')
  recursive_list(PasswordVault::VAULT).flatten.map do |f|
    raise unless f.starts_with?(prefix)
    f[prefix.length..-1]
  end.sort.join("\n")
end

# List the recipient keys on a given encrypted file.
# (This will be the ID of encryption subkeys, not the primary keys.)
def list_recipients(file_name)
  raise "No such file: #{file_name}" unless File.file?(file_name)
  output = nil
  status = Subprocess.popen(['gpg', '--list-only', '--verbose', file_name],
                            {:stderr=>Subprocess::PIPE}) do |_, _, _, err|
    output = err.read()
  end

  if status.exitstatus != 0
    puts output
    raise 'GPG list failed'
  end

  return output.scan(/^gpg: public key is (.+)$/).flatten
end

get '/:password_name/recipients/:alleged_requestor' do |password_name, alleged_requestor|
  password_name = PasswordVault.unescape(password_name)
  alleged_requestor = PasswordVault.unescape(alleged_requestor)
  file_name = File.join(PasswordVault::VAULT, password_name)
  if PasswordVault.name_ok?(password_name) and File.file?(file_name)
    recipients = list_recipients(file_name)
    content = recipients.join("\n") + "\n"
    reporter.report_recipients(password_name, alleged_requestor, :success => true)
  else
    reporter.report_recipients(password_name, alleged_requestor, :success => false)
    content = nil
  end

  content
end

get '/:password_name/:alleged_requestor' do |password_name, alleged_requestor|
  password_name = PasswordVault.unescape(password_name)
  alleged_requestor = PasswordVault.unescape(alleged_requestor)
  file_name = File.join(PasswordVault::VAULT, password_name)
  if PasswordVault.name_ok?(password_name) and File.file?(file_name)
    content = File.read(file_name)
    reporter.report_fetch(password_name, alleged_requestor, :success => true)
  else
    reporter.report_fetch(password_name, alleged_requestor, :success => false)
    content = nil
  end

  content
end

def recursive_rm(d)
  return if File.directory?(File.join(d, '.git')) # hack to avoid deleting vault
  if Dir.entries(d).length == 0
    FileUtils.rmdir(d)
    recursive_rm(File.dirname(d))
  end
end

get '/:password_name/delete/:alleged_requestor' do |password_name, alleged_requestor|
  password_name = PasswordVault.unescape(password_name)
  alleged_requestor = PasswordVault.unescape(alleged_requestor)
  file_name = File.join(PasswordVault::VAULT, password_name)

  if PasswordVault.name_ok?(password_name) and File.file?(file_name)
    reporter.report_rm(password_name, alleged_requestor, :success => true)
    commit_msg = "#{alleged_requestor}: Remove password #{password_name}"
    Subprocess.check_call(['git', 'rm', password_name], :cwd => PasswordVault::VAULT)
    Subprocess.check_call(['git', 'commit', '-m', commit_msg], :cwd => PasswordVault::VAULT)
    recursive_rm(File.dirname(file_name))
    response = "Thanks, #{alleged_requestor}, for removing #{password_name}\n"
  else
    reporter.report_rm(password_name, alleged_requestor, :success => false)
    response = "Sorry, #{alleged_requestor}, removing of #{password_name} failed\n"
  end
end

post '/:password_name/add/:alleged_requestor' do |password_name, alleged_requestor|
  password_name = PasswordVault.unescape(password_name)
  alleged_requestor = PasswordVault.unescape(alleged_requestor)
  file_name = File.join(PasswordVault::VAULT, password_name)
  if PasswordVault.name_ok?(password_name) and not params[:content].nil? and not File.directory?(file_name)
    # Time of check time of use race here
    if existed = File.file?(file_name)
      current_content = File.read(file_name)
      commit_msg = "#{alleged_requestor}: Update password #{password_name}"
    else
      current_content = nil
      commit_msg = "#{alleged_requestor}: Add password #{password_name}"
      FileUtils.mkdir_p(File.dirname(file_name))
    end

    if current_content != params[:content]
      File.open(file_name, 'w') do |f|
        f.write(params[:content])
      end

      Subprocess.check_call(['git', 'add', password_name], :cwd => PasswordVault::VAULT)
      Subprocess.check_call(['git', 'commit', '-m', commit_msg], :cwd => PasswordVault::VAULT)
    end

    if existed
      reporter.report_add(password_name, alleged_requestor,
                          :content => params[:content],
                          :success => true,
                          :existing => true)
      response = "Thanks, #{alleged_requestor}, for updating #{password_name}\n"
    else
      reporter.report_add(password_name, alleged_requestor,
                          :content => params[:content],
                          :success => true,
                          :existing => false)
      response = "Thanks, #{alleged_requestor}, for creating the new password #{password_name}\n"
    end
  else
    reporter.report_add(password_name, alleged_requestor, :success => false)
    response = "Sorry, #{alleged_requestor}, something went wrong with creation of #{password_name}\n"
  end
  response
end

if not File.directory?(PasswordVault::VAULT)
  $stderr.puts "Vault directory #{PasswordVault::VAULT} does not exist"
  exit(1)
end

begin
  Subprocess.check_call(['git', 'status'], :cwd => PasswordVault::VAULT)
rescue Subprocess::SpawnError
  $stderr.puts "Could not run git status in #{PasswordVault::VAULT}.  HINT: did you initialize a git repository there?"
  exit(2)
end

# Be uber-paranoid
File.umask(077)
