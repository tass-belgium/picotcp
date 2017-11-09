require 'test_helper'
require 'net/dns/rr'

class RRMXTest < Test::Unit::TestCase

  def setup
    @rr_name        = "example.com."
    @rr_type        = "MX"
    @rr_cls         = "IN"
    @rr_ttl         = 10000
    @rr_preference  = 10
    @rr_exchange    = "mail.example.com."
    @rr_value       = "#{@rr_preference} #{@rr_exchange}"

    @rr_output  = "example.com.            10000   IN      MX      10 mail.example.com."

    @rr         = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 10, :exchange => "mail.example.com.", :ttl => 10000)
  end


  def test_initialize_from_hash
    @record = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 10, :exchange => "mail.example.com.", :ttl => 10000)
    assert_equal @rr_output,      @record.to_s
    assert_equal @rr_name,        @record.name
    assert_equal @rr_type,        @record.type
    assert_equal @rr_cls,         @record.cls
    assert_equal @rr_ttl,         @record.ttl
    assert_equal @rr_preference,  @record.preference
    assert_equal @rr_exchange,    @record.exchange
  end

  def test_initialize_from_string
    @record = Net::DNS::RR::MX.new("example.com. 10000 IN MX 10 mail.example.com.")
    assert_equal @rr_output,      @record.to_s
    assert_equal @rr_name,        @record.name
    assert_equal @rr_type,        @record.type
    assert_equal @rr_cls,         @record.cls
    assert_equal @rr_ttl,         @record.ttl
    assert_equal @rr_preference,  @record.preference
    assert_equal @rr_exchange,    @record.exchange
  end

  # FIXME: can't get it working with canned data
  # def test_parse
  #   data = "\001\220\006google\003com\004s9b2\005psmtp\003com\000"
  #   @record = Net::DNS::RR.parse(data)
  #   assert_equal @rr_output,      @record.to_s
  #   assert_equal @rr_name,        @record.name
  #   assert_equal @rr_type,        @record.type
  #   assert_equal @rr_cls,         @record.cls
  #   assert_equal @rr_ttl,         @record.ttl
  #   assert_equal @rr_preference,  @record.preference
  #   assert_equal @rr_exchange,    @record.exchange
  # end


  InvalidArguments = [
    { :name => "google.com" },
    Object.new,
    Array.new(7),
    "10800 IN NS",
    "google.com. 10800 IN NS",
  ]

  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { p Net::DNS::RR::MX.new(arguments) }
    end
  end


  def test_preference
    @rr = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 10, :exchange => "mail.example.com.")
    assert_equal  10, @rr.preference

    @rr = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 100, :exchange => "mail.example.com.")
    assert_equal  100, @rr.preference
  end

  def test_exchange
    @rr = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 10, :exchange => "mail.example.com.")
    assert_equal  "mail.example.com.", @rr.exchange

    @rr = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 10, :exchange => "mail2.example.com.")
    assert_equal  "mail2.example.com.", @rr.exchange
  end

  def test_value
    @rr = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 10, :exchange => "mail.example.com.")
    assert_equal  "10 mail.example.com.", @rr.value

    @rr = Net::DNS::RR::MX.new(:name => "example.com.", :preference => 100, :exchange => "mail2.example.com.")
    assert_equal  "100 mail2.example.com.", @rr.value
  end


  def test_inspect
    assert_equal  "example.com.            10000   IN      MX      10 mail.example.com.",
                  @rr.inspect
  end

  def test_to_s
    assert_equal  "example.com.            10000   IN      MX      10 mail.example.com.",
                  @rr.to_s
  end

  def test_to_a
    assert_equal  ["example.com.", 10000, "IN", "MX", "10 mail.example.com."],
                  @rr.to_a
  end

end
