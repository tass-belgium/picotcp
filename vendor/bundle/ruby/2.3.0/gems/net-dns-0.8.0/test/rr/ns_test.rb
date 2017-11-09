require 'test_helper'
require 'net/dns/rr'

class RRNSTest < Test::Unit::TestCase

  def setup
    @rr_name    = "google.com."
    @rr_type    = "NS"
    @rr_cls     = "IN"
    @rr_ttl     = 10800
    @rr_nsdname = "ns1.google.com."
    
    @rr_output  = "google.com.             10800   IN      NS      ns1.google.com."

    @rr         = Net::DNS::RR::NS.new(:name => "google.com.", :nsdname => "ns1.google.com.", :ttl => @rr_ttl)
  end


  def test_initialize_from_hash
    @record = Net::DNS::RR::NS.new(:name => "google.com.", :nsdname => "ns1.google.com.")
    assert_equal @rr_output,  @record.inspect
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_nsdname, @record.nsdname
  end

  def test_initialize_from_string
    @record = Net::DNS::RR::NS.new("google.com. 10800 IN NS ns1.google.com.")
    assert_equal @rr_output,  @record.inspect
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_nsdname, @record.nsdname
  end

  def test_parse
    data = "\006google\003com\000\000\002\000\001\000\000*0\000\020\003ns1\006google\003com\000"
    @record = Net::DNS::RR.parse(data)
    assert_equal @rr_output,  @record.inspect
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_nsdname, @record.nsdname
  end


  InvalidArguments = [
    { :name => "google.com", :nsdname => "255.256" },
    { :name => "google.com" },
    Object.new,
    Array.new(7),
    "10800 IN A",
  ]
  
  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { Net::DNS::RR::NS.new(arguments) }
    end
  end


  def test_value
    assert_equal  "ns1.google.com.", @rr.value
  end


  def test_inspect
    assert_equal  "google.com.             10800   IN      NS      ns1.google.com.",
                  @rr.inspect
  end

  def test_to_s
    assert_equal  "google.com.             10800   IN      NS      ns1.google.com.",
                  @rr.to_s
  end

  def test_to_a
    assert_equal  ["google.com.", 10800, "IN", "NS", "ns1.google.com."],
                  @rr.to_a
  end

end
