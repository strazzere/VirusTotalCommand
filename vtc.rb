#! /usr/bin/env ruby
require 'rubygems'
require 'mechanize'
require 'json'
require 'digest/md5'
require 'digest/sha2'

APP_NAME        = "vtcommand"
VTC_VERSION     = "1.1"

LATEST          = "https://www.virustotal.com/file/"
LATEST_MID      = "/analysis/"
AGENT           = 'Mac Safari'

FILE_NAMES      = /<h5>File names <small>\(max. 25\)<\/small><\/h5>[<ol>\n|\s]+<li>[\n|\s]+([^\n]+)[\n|\s]+<\/li>/
FIRST_SEEN      = /<td>[\n|\s]+<h5>First seen by VirusTotal<\/h5>[\n|\s]+([\d\-\s\:]+UTC)\s\(\s([\d]+\s[\w\s]+)/
LAST_SEEN       = /<td>\n\s{15}<h5>Last seen by VirusTotal<\/h5>\n\s{15}([\d\-\s\:]+UTC)\s\(\s([\d]+\s[\w\s]+)/
DETECTION_RATIO = /<td>Detection ratio:<\/td>[\n|\s]+<[\w\s=\"\-]+>(\d\d\s\/\s\d\d)<\/td>/

def help
  info 'Usage: ' + APP_NAME + ' <options>'
  verbose 'Options:'
  verbose " -h/--hash HASH\t\t: Search for a single hash on virustotal.com (md5, sha1, sha256)"
  verbose " -f/--file FILE\t\t: Check a specific file for results on virustotal.com"
  verbose " -t/--time-stamp TIME\t: A specific time (epoc-based) to get results for"
  verbose " -?/-help\t\t: this help"
end

def info (string=nil)
  if(!string.nil?)
    puts " [*] " + string
  end
end

def error (string=nil)
  if(!string.nil?)
    puts " [!] Error: " + string
  end
end

def verbose (string=nil)
  if(!string.nil?)
    puts "    [+] " + string
  end
end

def get_information (hash=nil, time=nil)
  if(hash.nil?)
    raise RuntimeError.new 'The hash (sha256) of the sample is required to get information about it!'
  end

  if(time.nil?)
    time = Time.now.to_i.to_s
    verbose 'No time provided, using current time of [ ' + time.to_s + ' ]'
  else
    verbose 'Using provided timestamp of [ ' + time.to_s + ' ]'
  end

  mech = Mechanize.new
  file = {}
  mech.get(LATEST + hash + LATEST_MID + Time.now.to_i.to_s + '/') do |search|
    file[:file_names] = search.content.scan(FILE_NAMES)[0][0]
    file[:first_seen_utc] = search.content.scan(FIRST_SEEN)[0][0]
    file[:first_seen_human] = search.content.scan(FIRST_SEEN)[0][1]
    file[:last_seen_utc] = search.content.scan(LAST_SEEN)[0][0]
    file[:last_seen_human] = search.content.scan(LAST_SEEN)[0][1]
    file[:detection_ratio] = search.content.scan(DETECTION_RATIO)[0][0]
  end

  return file
end

def pretty_print(information=nil)
  if(information.nil?)
    raise RuntimeError.new 'Unable to print nil information!'
  end

  info 'Data retrieved from VT:'

  verbose 'File names:'
  information[:file_names].each do |name|
    verbose '  ' + name
  end

  verbose 'First seen:'
  verbose '  ' + information[:first_seen_utc] + ' - ' + information[:first_seen_human]
  verbose 'Last seen:'
  verbose '  ' + information[:last_seen_utc] + ' - ' + information[:last_seen_human]
end

if $stdin.tty?
  info "VTCommand v" + VTC_VERSION + " - Tim Strazzere (strazz@gmail.com)"

  ARGS = {}
  next_arg = nil
  ARGV.each do |arg|
    case arg
    when '-h', '--hash'
      next_arg = :hash
    when '-f', '--file'
      next_arg = :file
    when '-t', '--time-stamp'
      next_arg = :time_stamp
    when '-?', '--help'
      ARGS[:help] = true
      # Exit out
    else
      if ARGS[next_arg].nil?
        ARGS[next_arg] = arg
      end
    end
  end

  if(ARGS.length == 0 || ARGS[:help])
    help
  else
    information = nil
    ARGS.each do |option, value|
      case option
      when :hash
        verbose 'Processing hash [ ' + value.to_s + ' ]'
        information = get_information(value.to_s, ARGS[:time_stamp])
      when :file
        begin
          verbose 'Processing file [ ' + value.to_s + ' ]'
          sha_digest = Digest::SHA2.hexdigest(File.read(value))
          verbose "SHA256:\t[ " + sha_digest.to_s + " ]"

          information = get_information(sha_digest.to_s, ARGS[:time_stamp])
        rescue Errno::ENOENT
          error "\'" + file + "\' was not found!"
        end
      else
        next
        # Unknown option parsed
      end
      pretty_print information
  end
  end
end

