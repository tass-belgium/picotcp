# Net::DNS

Net::DNS is a DNS library written in pure Ruby. It started as a port of Perl Net::DNS module, but it evolved in time into a full Ruby library.  


## Features

- Complete OO interface
- Clean and intuitive API
- Modular and flexible


## Requirements

* Ruby >= 1.8.7


## Installation

The best way to install this library is via [RubyGems](https://rubygems.org/).

    $ gem install net-dns

You might need administrator privileges on your system to install the gem.


## API Documentation

Visit the page http://rdoc.info/gems/net-dns


## Trivial resolver

The simplest way to use the library is to invoke the Resolver() method:

    require 'rubygems' 
    require 'net/dns'
    p Resolver("www.google.com")

The output is compatible with BIND zone files and it's the same you would get with the dig utility.

    ;; Answer received from localhost:53 (212 bytes)
    ;;
    ;; HEADER SECTION
    ;; id = 64075
    ;; qr = 1       opCode: QUERY   aa = 0  tc = 0  rd = 1
    ;; ra = 1       ad = 0  cd = 0  rcode = NoError
    ;; qdCount = 1  anCount = 3     nsCount = 4     arCount = 4
    
    ;; QUESTION SECTION (1 record):
    ;; google.com.                  IN      A
    
    ;; ANSWER SECTION (3 records):
    google.com.             212     IN      A       74.125.45.100
    google.com.             212     IN      A       74.125.67.100
    google.com.             212     IN      A       209.85.171.100
    
    ;; AUTHORITY SECTION (4 records):
    google.com.             345512  IN      NS      ns1.google.com.
    google.com.             345512  IN      NS      ns4.google.com.
    google.com.             345512  IN      NS      ns2.google.com.
    google.com.             345512  IN      NS      ns3.google.com.
    
    ;; ADDITIONAL SECTION (4 records):
    ns1.google.com.         170275  IN      A       216.239.32.10
    ns2.google.com.         170275  IN      A       216.239.34.10
    ns3.google.com.         170275  IN      A       216.239.36.10
    ns4.google.com.         170275  IN      A       216.239.38.10

An optional block can be passed yielding the Net::DNS::Packet object

    Resolver("www.google.com") { |packet| puts packet.size + " bytes" }
    # => 484 bytes

Same for Net::DNS::Resolver.start():

    Net::DNS::Resolver.start("google.com").answer.size
    # => 5

As optional parameters, +TYPE+ and +CLASS+ can be specified.

    p Net::DNS::Resolver.start("google.com", Net::DNS::MX)
    
    ;; Answer received from localhost:53 (316 bytes)
    ;;
    ;; HEADER SECTION
    ;; id = 59980
    ;; qr = 1       opCode: QUERY   aa = 0  tc = 0  rd = 1
    ;; ra = 1       ad = 0  cd = 0  rcode = NoError
    ;; qdCount = 1  anCount = 4     nsCount = 4     arCount = 8
    
    ;; QUESTION SECTION (1 record):
    ;; google.com.                  IN      MX
    
    ;; ANSWER SECTION (4 records):
    google.com.             10800   IN      MX      10 smtp2.google.com.
    google.com.             10800   IN      MX      10 smtp3.google.com.
    google.com.             10800   IN      MX      10 smtp4.google.com.
    google.com.             10800   IN      MX      10 smtp1.google.com.


## Handling the response packet

The method Net::DNS::Resolver.start is a wrapper around Resolver.new. It returns a new Net::DNS::Packet object.

A DNS packet is divided into 5 sections:

- header section # => a Net::DNS::Header object
- question section # => a Net::DNS::Question object
- answer section # => an Array of Net::DNS::RR objects
- authority section # => an Array of Net::DNS::RR objects
- additional section # => an Array of Net::DNS::RR objects

You can access each section by calling the attribute with the same name on a Packet object:

    packet = Net::DNS::Resolver.start("google.com")
    
    header = packet.header
    answer = packet.answer
    
    puts "The packet is #{packet.data.size} bytes"
    puts "It contains #{header.anCount} answer entries"
    
    answer.any? {|ans| p ans}
    
The output is 

    The packet is 378 bytes
    It contains 3 answer entries
    google.com.             244     IN      A       74.125.45.100
    google.com.             244     IN      A       74.125.67.100
    google.com.             244     IN      A       209.85.171.100

A better way to handle the answer section is to use the iterators directly on a Packet object:

    packet.each_address do |ip|
      puts "#{ip} is alive" if Ping.pingecho(ip.to_s, 10, 80)
    end

Gives:

    74.125.45.100 is alive
    74.125.67.100 is alive
    209.85.171.100 is alive


## License

Net::DNS is distributed under the same license Ruby is.


## Authors

- Marco Ceresa (@bluemonk)
- Simone Carletti (@weppos)
