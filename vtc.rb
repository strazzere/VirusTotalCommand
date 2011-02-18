#! /usr/bin/env ruby
require 'rubygems'
require 'mechanize'
require 'json'
require 'digest/md5'
require 'digest/sha1'

VER = "1.0"

LATEST = "http://www.virustotal.com/latest-report.html?resource="
WORKLOAD = "http://www.virustotal.com/get_workload.json?_="
UPDATES = "http://www.virustotal.com/get_updates.json?_="
AGENT = 'Mac Safari'

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


def latest_for_hash (hash=nil)
  if(!hash.nil?)
    mech = Mechanize.new
    mech.get LATEST + hash do |search|
      file = []
      file<< {:file_name => search.content.scan(/<span id=\"status-object\" class=\"blackthick\">(.*?)<\/span>/)}
      file<< {:submission_date => search.content.scan(/<span id=\"status-date\" class=\"blackthick\">(.*?)<\/span>/)}
      file<< {:submission_status => search.content.scan(/<span id=\"status-status\" class=\"blackthick\">(.*?)<\/span>/)}
      file<< {:detection_num => search.content.scan(/<span id=\"porcentaje\" style=\"color: red\">([0-9]+)<\/span>/)}
      file<< {:total_scanned_with => search.content.scan(/<span id=\"status-total\">\/([0-9]+) \(([0-9.]+)%\)<\/span>/)[0][0]}
      file<< {:detection_percentage => search.content.scan(/<span id=\"status-total\">\/([0-9]+) \(([0-9.]+)%\)<\/span>/)[0][1]}
      file<< {:community_percentage => search.content.scan(/<span style=\"font-size: 0.8em;\">&nbsp;Safety score: ([0-9.]+)%&nbsp;<\/span>/)}
      puts file.to_json
    end
  end
end

def get_updates (time=nil)
  mech = Mechanize.new
  mech.user_agent_alias = AGENT
  if(time.nil?)
    time = Time.now.to_i.to_s
  end
  mech.get UPDATES + time do |updates|
    return JSON.parse(updates.content.to_s)
  end
end

def get_workload (time=nil)
  mech = Mechanize.new
  mech.user_agent_alias = AGENT
  if(time.nil?)
    time = Time.now.to_i.to_s
  end
  mech.get WORKLOAD + time do |workload|
    return JSON.parse(workload.content)
  end
end

def display_updates
  info "Querying for updates..."
  status = get_updates nil
  if(!status.nil?)
    if(!status['updates'].nil?)
      if(status['updates'] == 0)
        update_str = "No updates found."
      else
        update_str = "Updates found!"
      end
      verbose update_str + " Updates variable: [ " + status['updates'].to_s + " ]"
    end
    if(!status['detail'].nil?)
      if(status['detail'] == "")
        detail_str = "No details found. "
      else
        detail_str = "Details found, (not normal)!"
      end
      verbose detail_str + " Details: [ " + status['detail'].to_s + " ]"
    end
  end
end

def display_workload
  info "Querying for workload..."
  status = get_workload nil
  if(!status.nil?)
    if(!status['url'].nil?)
      if(status['url'] == "1")
        url_str = "URL workload appears fine."
      else
        url_str = "Unknown URL workload found!"
      end
      verbose url_str + " URL Load: [ " + status['url'].to_s + " ]"
    end
    if(!status['file'].nil?)
      if(status['file'] == 1)
        file_str = "File workload appears fine."
      else
        file_str = "Unknown file workload found!"
      end
      verbose file_str + " File Load: [ " + status['file'].to_s + " ]"
    end
  end
end

if $stdin.tty?
  info "VTCommand v" + VERSION + " - Tim Strazzere (strazz@gmail.com)"
  if(ARGV.length == 0)
    help
  end
  ARGV.each do |file|
    begin
      latest_for_hash "5192ad05597e7a148f642be43f6441f6"
      md5_digest = Digest::MD5.hexdigest(File.read(file))
      sha_digest = Digest::SHA1.hexdigest(File.read(file))
      display_workload
      display_updates
    rescue Errno::ENOENT
      error "\'" + file + "\' was not found!"
    end
  end
end