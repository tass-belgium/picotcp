require 'test_helper'
require 'net/dns/question'

class QuestionTest < Test::Unit::TestCase

  def setup
    @domain = 'example.com.'
    @type   = 'MX'
    @cls  = 'HS'
    @data = "\006google\003com\000\000\001\000\001"

    @default = Net::DNS::Question.new(@domain)
    @string  = Net::DNS::Question.new(@domain,@type,@cls)
    @binary  = Net::DNS::Question.parse(@data)
    @binary2 = Net::DNS::Question.parse(@string.data)
  end

  def test_simple
    assert_equal(@default.qName, @domain)
    assert_equal(@default.qType.to_s, "A")
    assert_equal(@default.qClass.to_s, "IN")

    assert_equal(@string.qName, @domain)
    assert_equal(@string.qType.to_s, "MX")
    assert_equal(@string.qClass.to_s, "HS")

    assert_equal(@binary.qName, "google.com.")
    assert_equal(@binary.qType.to_s, "A")
    assert_equal(@binary.qClass.to_s, "IN")

    assert_equal(@binary2.qName, @domain)
    assert_equal(@binary2.qType.to_s, "MX")
    assert_equal(@binary2.qClass.to_s, "HS")
  end

  def test_raise
    # assert_raises(Net::DNS::Question::NameInvalid) do
    #   Net::DNS::Question.new(1)
    # end
    assert_raises(Net::DNS::Question::NameInvalid) do
      Net::DNS::Question.new("test{")
    end
    assert_raises(ArgumentError) do
      Net::DNS::Question.parse(Array.new)
    end
    assert_raises(ArgumentError) do
      Net::DNS::Question.parse("test")
    end
  end

  def test_inspect
    assert_equal  "google.com.                  IN      A       ",
                  Net::DNS::Question.new("google.com.").inspect
    assert_equal  "google.com.                  IN      A       ",
                  Net::DNS::Question.new("google.com.", Net::DNS::A).inspect
    assert_equal  "google.com.                  IN      NS      ",
                  Net::DNS::Question.new("google.com.", Net::DNS::NS).inspect
    assert_equal  "google.com.                  IN      NS      ",
                  Net::DNS::Question.new("google.com.", Net::DNS::NS).inspect
  end

  def test_inspect_with_name_longer_than_29_chrs
    assert_equal  "supercalifragilistichespiralidoso.com IN      A       ",
                  Net::DNS::Question.new("supercalifragilistichespiralidoso.com").inspect
  end

  def test_to_s
    assert_equal  "google.com.                  IN      A       ",
                  Net::DNS::Question.new("google.com.").to_s
    assert_equal  "google.com.                  IN      A       ",
                  Net::DNS::Question.new("google.com.", Net::DNS::A).to_s
    assert_equal  "google.com.                  IN      NS      ",
                  Net::DNS::Question.new("google.com.", Net::DNS::NS).to_s
    assert_equal  "google.com.                  IN      NS      ",
                  Net::DNS::Question.new("google.com.", Net::DNS::NS).to_s
  end

  def test_to_s_with_name_longer_than_29_chrs
    assert_equal  "supercalifragilistichespiralidoso.com IN      A       ",
                  Net::DNS::Question.new("supercalifragilistichespiralidoso.com").to_s
  end

end
