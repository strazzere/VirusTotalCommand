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
FILE_SIZE       = /<td>File size:<\/td>[\n|\s]+<td>([\w|\s\.\(\)]+)<\/td>/ 
FILE_TYPE       = /<td>File type:<\/td>[\n|\s]+<td>([\w|\s]+)<\/td>/
DETECTION_RATIO = /<td>Detection ratio:<\/td>[\n|\s]+<[\w\s=\"\-]+>(\d\d)\s\/\s(\d\d)<\/td>/
EXIF_METADATA   = /<h5>ExifTool file metadata<\/h5>\s+<pre.*>([.\S\s]+)<\/pre>/
SSDEEP          = /<h5>ssdeep<\/h5>[\n|\s]+([\w|0-9\:]+)/

def help
  info 'Usage: ' + APP_NAME + ' <options>'
  verbose 'Options:'
  verbose " -h/--hash HASH\t\t: Search for a single hash on virustotal.com (md5, sha1, sha256)"
  verbose " -f/--file FILE\t\t: Check a specific file for results on virustotal.com"
  verbose " -t/--time-stamp TIME\t: A specific time (epoc-based) to get results for"
  verbose " -p/--proxy PROXY:PORT\t: A specific proxy and port address to use "
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

def get_information (hash=nil, time=nil, proxy=nil)
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

  if(proxy)
    verbose 'Using proided proxy of [ ' + proxy[0] + ':' + proxy[1] + ' ]'
    mech.set_proxy(proxy[0], proxy[1])
  end

  file = {}
  mech.get(LATEST + hash + LATEST_MID + Time.now.to_i.to_s + '/') do |search|

    file_names = search.content.scan(FILE_NAMES)
    if(!file_names.nil? && !file_names[0].nil? && !file_names[0][0].nil?)
      file[:file_names] = file_names[0][0]
    end

    first_seen_utc = search.content.scan(FIRST_SEEN)
    if(!first_seen_utc.nil? && !first_seen_utc[0].nil? && !first_seen_utc[0][0].nil? && !first_seen_utc[0][1].nil?)
      file[:first_seen_utc] = first_seen_utc[0][0]
      file[:first_seen_human] = first_seen_utc[0][1]
    end

    last_seen_utc = search.content.scan(LAST_SEEN)
    if(!last_seen_utc.nil? && !last_seen_utc[0].nil? && !last_seen_utc[0][0].nil? && !last_seen_utc[0][1].nil?)
      file[:last_seen_utc] = last_seen_utc[0][0]
      file[:last_seen_human] = last_seen_utc[0][1]
    end

    file_size = search.content.scan(FILE_SIZE)
    if(!file_size.nil? && !file_size[0].nil? && !file_size[0][0].nil?)
      file[:file_size] = file_size[0][0]
    end

    file_type = search.content.scan(FILE_TYPE)
    if(!file_type.nil? && !file_type[0].nil? && !file_type[0][0].nil?)
      file[:file_type] = file_type[0][0]
    end

    detection_ratio = search.content.scan(DETECTION_RATIO)
    if(!detection_ratio.nil? && !detection_ratio[0].nil?)
      file[:detection_ratio] = detection_ratio[0]
    end

    exif_metadata = search.content.scan(EXIF_METADATA)
    if(!exif_metadata.nil? && !exif_metadata[0].nil? && !exif_metadata[0][0].nil?)
      file[:exif_metadata] = exif_metadata[0][0]
    end

    ssdeep = search.content.scan(SSDEEP)
    if(!ssdeep.nil? && !ssdeep[0].nil? && !ssdeep[0][0].nil?)
      file[:ssdeep] = ssdeep[0][0]
    end
  end

  return file
end

def pretty_print(information=nil)
  if(information.nil?)
    raise RuntimeError.new 'Unable to print nil information!'
  end

  info 'Data retrieved from VirusTotal:'

  information.each do |key, value|
    buffer = ''
    case key
    when :file_names
      buffer += "File names:\n"
      value.each do |name|
          buffer += "\t" + name
      end
    when :first_seen_utc
      buffer = "First seen:\n" +
        "\t" + value + " - " + information[:first_seen_human]
    when :last_seen_utc
      buffer = "Last seen:\n" +
        "\t" + value + " - " + information[:last_seen_human]
    when :first_seen_human, :last_seen_human
    when :file_size
      buffer = "File size:\n" + "\t" + value.to_s
    when :file_type
      buffer = "File type:\n" + "\t" + value.to_s
    when :detection_ratio
      percentage = (information[:detection_ratio][0].to_f / information[:detection_ratio][1].to_f * 100).to_i.to_s
      buffer = "Detection Percentage:\n" +
        "\t" + percentage + "% (" + information[:detection_ratio][0] + "/" + information[:detection_ratio][1] + ")"
    when :exif_metadata
      exif_metadata = "Exif Metadata:\n"
      value.split("\n").each do |metadata|
        exif_metadata += "\t" + metadata + "\n"
      end
      buffer = exif_metadata
    when :ssdeep
      buffer = "SSDEEP:\n" + "\t" + value
    else
      error 'Hit an unknown option to print : ' + key.to_s
    end
    verbose buffer if buffer != ''
  end
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
    when '-p', '--proxy'
      next_arg = :proxy_address
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

    if(ARGS[:proxy_address])
      proxy = ARGS[:proxy_address].split(':')
    end

    information = nil
    ARGS.each do |option, value|
      case option
      when :hash
        verbose 'Processing hash [ ' + value.to_s + ' ]'
        information = get_information(value.to_s, ARGS[:time_stamp], proxy)
      when :file
        begin
          verbose 'Processing file [ ' + value.to_s + ' ]'
          sha_digest = Digest::SHA2.hexdigest(File.read(value))
          verbose "SHA256:\t[ " + sha_digest.to_s + " ]"

          information = get_information(sha_digest.to_s, ARGS[:time_stamp], proxy)
        rescue Net::HTTP::Persistent::Error
          error 'Either VirusTotal is down - or a bad proxy was used!'
        rescue Errno::ENOENT
          error "\'" + value + "\' was not found!"
        end
      else
        next
        # Unknown option parsed
      end

      if(information)
        pretty_print information
      end
  end
  end
end

