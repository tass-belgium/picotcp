require 'test_helper'
require 'net/dns/rr'

class RRMRTest < Test::Unit::TestCase

  def setup
    @klass      = Net::DNS::RR::MR
    @rr         = @klass.new(:name => "eddie.movie.edu.", :newname => "eddie.bornagain.edu.", :ttl => 9000)

    @rr_name    = "eddie.movie.edu."
    @rr_type    = "MR"
    @rr_cls     = "IN"
    @rr_ttl     = 9000
    @rr_newname = "eddie.bornagain.edu."
    @rr_value   = "eddie.bornagain.edu."
    @rr_output  = "eddie.movie.edu.        9000    IN      MR      eddie.bornagain.edu."
  end


  def test_initialize_from_hash
    @record = @klass.new(:name => "eddie.movie.edu.", :newname => "eddie.bornagain.edu.", :ttl => 9000)
    assert_equal @rr_output,  @record.inspect
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_newname, @record.newname
  end

  def test_initialize_from_string
    @record = @klass.new("eddie.movie.edu.  9000  IN  MR  eddie.bornagain.edu.")
    assert_equal @rr_output,  @record.inspect
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_newname, @record.newname
  end

  # def test_parse
  #   data = "\005eddie\005movie\003edu\000\000\t\000\001\000\000#(\000\025\005eddie\tbornagain\003edu\000"
  #   @record = Net::DNS::RR.parse(data)
  #   assert_equal @rr_output,  @record.inspect
  #   assert_equal @rr_name,    @record.name
  #   assert_equal @rr_type,    @record.type
  #   assert_equal @rr_cls,     @record.cls
  #   assert_equal @rr_ttl,     @record.ttl
  #   assert_equal @rr_newname, @record.newname
  # end


  InvalidArguments = [
    # FIXME: { :name => "eddie.movie.edu.", :newname => "foo___bar" },
    # FIXME: { :name => "eddie.movie.edu.", :newname => "foo$bar" },
    # FIXME: { :name => "eddie.movie.edu", :newname => "eddie.newname.edu." },
    Object.new,
    Array.new(7),
    "9000  IN  MR",
  ]

  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { @klass.new(arguments) }
    end
  end

  def test_initialize_should_raise_with_missing_newname
    error = assert_raises(ArgumentError) { @klass.new(:name => "eddie.movie.edu.") }
    assert_match /:newname/, error.message
  end


  def test_value
    @rr = @klass.new(:name => "eddie.movie.edu.", :newname => "eddie.newname.edu.")
    assert_equal  "eddie.newname.edu.", @rr.value

    @rr = @klass.new(:name => "eddie.movie.edu.", :newname => "eddie.othername.edu.")
    assert_equal  "eddie.othername.edu.", @rr.value
  end

  def test_newname
    @rr = @klass.new(:name => "eddie.movie.edu.", :newname => "eddie.newname.edu.")
    assert_equal  "eddie.newname.edu.", @rr.newname

    @rr = @klass.new(:name => "eddie.movie.edu.", :newname => "eddie.othername.edu.")
    assert_equal  "eddie.othername.edu.", @rr.newname
  end


  def test_inspect
    assert_equal  "eddie.movie.edu.        9000    IN      MR      eddie.bornagain.edu.",
                  @rr.inspect
  end

  def test_to_s
    assert_equal  "eddie.movie.edu.        9000    IN      MR      eddie.bornagain.edu.",
                  @rr.to_s
  end

  def test_to_a
    assert_equal  ["eddie.movie.edu.", 9000, "IN", "MR", "eddie.bornagain.edu."],
                  @rr.to_a
  end

end
