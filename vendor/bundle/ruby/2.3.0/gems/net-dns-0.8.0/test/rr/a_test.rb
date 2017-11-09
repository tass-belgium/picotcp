require 'test_helper'
require 'net/dns/rr'

class RRATest < Test::Unit::TestCase

  def setup
    @rr_name    = "google.com."
    @rr_type    = "A"
    @rr_cls     = "IN"
    @rr_ttl     = 10000
    @rr_value   = "64.233.187.99"
    @rr_address = IPAddr.new(@rr_value)

    @rr_output  = "google.com.             10000   IN      A       64.233.187.99"

    @rr         = Net::DNS::RR::A.new(:name => @rr_name, :address => @rr_address, :ttl => @rr_ttl)
  end


  def test_initialize_from_hash
    @record = Net::DNS::RR::A.new(:name => @rr_name, :address => @rr_value, :ttl => @rr_ttl)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_address, @record.address
    assert_equal @rr_value,   @record.value
  end

  def test_initialize_from_string
    @record = Net::DNS::RR::A.new("#{@rr_name} #{@rr_ttl} #{@rr_cls} #{@rr_type} #{@rr_value}")
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_address, @record.address
    assert_equal @rr_value,   @record.value
  end

  def test_parse
    data = "\006google\003com\000\000\001\000\001\000\000'\020\000\004@\351\273c"
    @record = Net::DNS::RR.parse(data)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_address, @record.address
    assert_equal @rr_value,   @record.value
  end


  InvalidArguments = [
    { :name => "google.com", :address => "255.256" },
    { :name => "google.com" },
    Object.new,
    Array.new(7),
    "10800 IN A",
    "google.com. 10800 IN B",
    "google.com. 10800 IM A",
  ]

  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { Net::DNS::RR::A.new(arguments) }
    end
  end


  def test_address_getter
    assert_equal  @rr_address, @rr.address
  end

  def test_address_setter
    assert_raises(ArgumentError) { @rr.address = nil }

    expected = IPAddr.new("64.233.187.99")
    assert_equal expected, @rr.address = "64.233.187.99"
    assert_equal expected, @rr.address

    expected = IPAddr.new("64.233.187.90")
    assert_equal expected, @rr.address = 1089059674
    assert_equal expected, @rr.address

    expected = IPAddr.new("64.233.187.80")
    assert_equal expected, @rr.address = IPAddr.new("64.233.187.80")
    assert_equal expected, @rr.address
  end


  def test_value
    assert_equal  @rr_value, @rr.value
  end


  def test_inspect
    assert_equal  "google.com.             10000   IN      A       64.233.187.99",
                  @rr.inspect
  end

  def test_to_s
    assert_equal  "google.com.             10000   IN      A       64.233.187.99",
                  @rr.to_s
  end

  def test_to_a
    assert_equal  ["google.com.", 10000, "IN", "A", "64.233.187.99"],
                  @rr.to_a
  end

end
