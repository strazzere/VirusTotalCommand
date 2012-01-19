#! /usr/bin/env ruby
require 'rubygems'
require 'mechanize'
require 'json'
require 'digest/md5'
require 'digest/sha2'

VTC_VERSION = "1.1"

LATEST = "https://www.virustotal.com/file/"
LATEST_MID = "/analysis/"
AGENT = 'Mac Safari'

FILE_NAMES = /<h5>File names <small>\(max. 25\)<\/small><\/h5>[<ol>\n|\s]+<li>[\n|\s]+([^\n]+)[\n|\s]+<\/li>/
FIRST_SEEN = /<td>[\n|\s]+<h5>First seen by VirusTotal<\/h5>[\n|\s]+([\d\-\s\:]+UTC)\s\(\s([\d]+\s[\w\s]+)/
LAST_SEEN  = /<td>\n\s{15}<h5>Last seen by VirusTotal<\/h5>\n\s{15}([\d\-\s\:]+UTC)\s\(\s([\d]+\s[\w\s]+)/
DETECTION_RATIO = /<td>Detection ratio:<\/td>[\n|\s]+<[\w\s=\"\-]+>(\d\d\s\/\s\d\d)<\/td>/

def help
  puts "Commands --"
  puts ""
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
  end

  mech = Mechanize.new
  file = []
  mech.get(LATEST + hash + LATEST_MID + Time.now.to_i.to_s + '/') do |search|
    file<< {
      :file_names => search.content.scan(FILE_NAMES)[0][0]
    }
    file<< {
      :first_seen_utc => search.content.scan(FIRST_SEEN)[0][0],
      :first_seen_human => search.content.scan(FIRST_SEEN)[0][1]
    }
    file<< {
      :last_seen_utc => search.content.scan(LAST_SEEN)[0][1],
      :last_seen_human => search.content.scan(LAST_SEEN)[0][1]
    }
    file<< {
      :detection_ratio => search.content.scan(DETECTION_RATIO)[0][0]
    }
  end

  return file
end

if $stdin.tty?
  info "VTCommand v" + VTC_VERSION + " - Tim Strazzere (strazz@gmail.com)"
  if(ARGV.length == 0)
    help
  end
  ARGV.each do |file|
    begin
      verbose 'Processing file [ ' + file.to_s + ' ]'
      md5_digest = Digest::MD5.hexdigest(File.read(file))
      sha_digest = Digest::SHA2.hexdigest(File.read(file))
      verbose "MD5:\t[ " + md5_digest.to_s + " ]"
      verbose "SHA256:\t[ " + sha_digest.to_s + " ]"
      info = get_information sha_digest.to_s
      puts info
    rescue Errno::ENOENT
      error "\'" + file + "\' was not found!"
    end
  end
end
