require 'test_helper'
require 'net/dns/rr'
require 'net/dns/rr/hinfo'

class RRHINFOTest < Test::Unit::TestCase

  def setup
    @rr_name    = ""
    @rr_type    = "HINFO"
    @rr_cls     = "IN"
    @rr_ttl     = nil
    @rr_value   = %Q{"PC-Intel-700mhz" "Redhat Linux 7.1"}
    @rr_output  = %Q{                                IN      HINFO   "PC-Intel-700mhz" "Redhat Linux 7.1"}

    @rr_cpu     = "PC-Intel-700mhz"
    @rr_os      = "Redhat Linux 7.1"

    @rr         = Net::DNS::RR::HINFO.new(:name => @rr_name, :cpu => @rr_cpu, :os => @rr_os)
  end


  def test_initialize_from_hash
    @record = Net::DNS::RR::HINFO.new(:name => @rr_name, :cpu => @rr_cpu, :os => @rr_os)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal 10800,       @record.ttl
    assert_equal @rr_value,   @record.value

    assert_equal @rr_cpu,     @record.cpu
    assert_equal @rr_os,      @record.os
  end

  def test_initialize_from_string
    @record = Net::DNS::RR::HINFO.new(%Q{#{@rr_name} #{@rr_ttl} #{@rr_cls} #{@rr_type} PC-Intel-700mhz "Redhat Linux 7.1"})
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_value,   @record.value

    assert_equal @rr_cpu,     @record.cpu
    assert_equal @rr_os,      @record.os
  end

  def test_initialize_from_string_without_quotes
    @record = Net::DNS::RR::HINFO.new("#{@rr_name} #{@rr_ttl} #{@rr_cls} #{@rr_type} #{@rr_value}")
    assert_equal @rr_output,  @record.to_s
    # FIXME: assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal 10800,       @record.ttl
    assert_equal @rr_value,   @record.value

    assert_equal @rr_cpu,     @record.cpu
    assert_equal @rr_os,      @record.os
  end

  # FIXME: Can't get valid data
  # def test_parse
  #   data = "\002in\000\000\r\000\001\000\000*0\000!\017PC-Intel-700mhz\020Redhat Linux 7.1"
  #   @record = Net::DNS::RR.parse(data)
  #   assert_equal @rr_output,  @record.to_s
  #   assert_equal @rr_name,    @record.name
  #   assert_equal @rr_type,    @record.type
  #   assert_equal @rr_cls,     @record.cls
  #   assert_equal @rr_ttl,     @record.ttl
  #   assert_equal @rr_value,   @record.value
  #
  #   assert_equal @rr_cpu,     @record.cpu
  #   assert_equal @rr_os,      @record.os
  # end


  InvalidArguments = [
    { :name => "google.com" },
    Object.new,
    Array.new(7),
    "10800 IN HINFO",
    "IN HINFO",
  ]

  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { p Net::DNS::RR::HINFO.new(arguments) }
    end
  end


  def test_cpu
    assert_equal  @rr_cpu, @rr.cpu
  end

  def test_os
    assert_equal  @rr_os, @rr.os
  end


  def test_value
    assert_equal  %Q{"PC-Intel-700mhz" "Redhat Linux 7.1"}, @rr.value
  end


  def test_inspect
    assert_equal  %Q{                                IN      HINFO   "PC-Intel-700mhz" "Redhat Linux 7.1"},
                  @rr.inspect
  end

  def test_to_s
    assert_equal  %Q{                                IN      HINFO   "PC-Intel-700mhz" "Redhat Linux 7.1"},
                  @rr.to_s
  end

  def test_to_a
    assert_equal  [nil, nil, "IN", "HINFO", %Q{"PC-Intel-700mhz" "Redhat Linux 7.1"}],
                  @rr.to_a
  end

end
