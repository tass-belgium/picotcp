require 'test_helper'
require 'net/dns/packet'

class PacketTest < Test::Unit::TestCase

  def setup
    @klass  = Net::DNS::Packet
    @domain = 'example.com'
  end

  def test_initialize
    @record = @klass.new(@domain, Net::DNS::MX, Net::DNS::HS)
    assert_instance_of @klass,              @record
    assert_instance_of Net::DNS::Header,    @record.header
    assert_instance_of Array,               @record.question
    assert_instance_of Net::DNS::Question,  @record.question.first
    assert_instance_of Array,               @record.answer
    assert_instance_of Array,               @record.authority
    assert_instance_of Array,               @record.additional
  end

  def test_initialize_should_set_question
    @question = @klass.new(@domain).question.first
    assert_equal @domain, @question.qName
    assert_equal Net::DNS::RR::Types.new(Net::DNS::A).to_s, @question.qType.to_s
    assert_equal Net::DNS::RR::Classes.new(Net::DNS::IN).to_s, @question.qClass.to_s 

    @question = @klass.new(@domain, Net::DNS::MX, Net::DNS::HS).question.first
    assert_equal @domain, @question.qName
    assert_equal Net::DNS::RR::Types.new(Net::DNS::MX).to_s, @question.qType.to_s
    assert_equal Net::DNS::RR::Classes.new(Net::DNS::HS).to_s, @question.qClass.to_s
  end

  def test_self_parse
    packet = "\337M\201\200\000\001\000\003\000\004\000\004\006google\003com\000\000\001\000\001\300\f\000\001\000\001\000\000\001,\000\004@\351\273c\300\f\000\001\000\001\000\000\001,\000\004H\016\317c\300\f\000\001\000\001\000\000\001,\000\004@\351\247c\300\f\000\002\000\001\000\003\364\200\000\006\003ns1\300\f\300\f\000\002\000\001\000\003\364\200\000\006\003ns2\300\f\300\f\000\002\000\001\000\003\364\200\000\006\003ns3\300\f\300\f\000\002\000\001\000\003\364\200\000\006\003ns4\300\f\300X\000\001\000\001\000\003\307\273\000\004\330\357 \n\300j\000\001\000\001\000\003\307\273\000\004\330\357\"\n\300|\000\001\000\001\000\003\307\273\000\004\330\357$\n\300\216\000\001\000\001\000\003\307\273\000\004\330\357&\n"
    @record = @klass.parse(packet)
    assert_instance_of @klass,              @record
    assert_instance_of Net::DNS::Header,    @record.header
    assert_instance_of Array,               @record.question
    assert_instance_of Net::DNS::Question,  @record.question.first
    assert_instance_of Array,               @record.answer
    assert_instance_of Net::DNS::RR::A,     @record.answer.first
    assert_instance_of Array,               @record.authority
    assert_instance_of Net::DNS::RR::NS,    @record.authority.first
    assert_instance_of Array,               @record.additional
    assert_instance_of Net::DNS::RR::A,     @record.additional.first
  end

end    
