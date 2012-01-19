VirusTotalCommand
===

VirusTotalCommand (vtc) is [virustotal](http://www.virustotal.com) convenience tool for file and URL submission.
It is an attempt to make a better version that ruby-virustotal, by avoiding the API key requirement and providing
more information to the user.

There are often reasons to not submit samples/applications to VirusTotal - this helps to automate that specific
need. This also makes it easier to search for specific analysis times and pull up retroactive information that
is not always be surfaced easily by the VT ui.

Requirements
---
 - `ruby (or jruby)`
 - `mechanize gem`
 - `json gem`

Installation
---
 - install required gems:
  - `gem install mechanize`
  - `gem install json`

Usage
---

Currently just run the script and pass any files you would like to get information for;

	  tstrazzere@spinach:~/repo/VirusTotalCommand$ ./vtc.rb ~/Downloads/com.android.bot.apk ~/Downloads/8ab0d7276837b96bff42867fc7c09981c26727be.apk
	   [*] VTCommand v1.1 - Tim Strazzere (strazz@gmail.com)
	       [+] Processing file [ /home/tstrazzere/Downloads/com.android.bot.apk ]
	       [+] MD5:	   [ 56033daef6a020d8e64729acb103f818 ]
	       [+] SHA256:	   [ 213e042b3d5b489467c5a461ffdd2e38edaa0c74957f0b1a0708027e66080890 ]
               [+] No time provided, using current time of [ 1326934107 ]
	   [*] Data retrieved from VT:
	       [+] File names:
    	       [+]   MADDEN_NFL_12_1.0.3._INFECTED.apk
    	       [+] First seen:
    	       [+]   2012-01-09 02:42:35 UTC - 1 week
    	       [+] Last seen:
    	       [+]   2012-01-15 18:18:19 UTC - 3 days
    	       [+] Processing file [ /home/tstrazzere/Downloads/8ab0d7276837b96bff42867fc7c09981c26727be.apk ]
    	       [+] MD5:	   [ 616a94fbbfb65d7b7c5a0e9afb73e784 ]
    	       [+] SHA256:	   [ d42757d4771b677cb4792e0934eddc8762c05ac25715470cbfbd9d5215e756a9 ]
    	       [+] No time provided, using current time of [ 1326934108 ]
 	   [*] Data retrieved from VT:
    	       [+] File names:
    	       [+]   1.apk
    	       [+] First seen:
    	       [+]   2011-03-22 04:28:47 UTC - 10 months ago 
    	       [+] Last seen:
    	       [+]   2012-01-18 15:17:44 UTC - 9 hours

