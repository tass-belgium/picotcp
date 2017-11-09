require 'test_helper'
require 'net/dns/header'

class HeaderTest < Test::Unit::TestCase
  include Net::DNS
  
  def setup

    @default = Header.new
    @hash = Header.new(:id => 441,
                       :qr => 1,
                       :opCode => Header::IQUERY,
                       :aa => 1,
                       :tc => 1,
                       :rd => 0,
                       :cd => 0,
                       :ad => 0,
                       :ra => 1,
                       :rCode => Header::RCode::FORMAT,
                       :qdCount => 1,
                       :anCount => 2,
                       :nsCount => 3,
                       :arCount => 3)
    
    @modified = Header.new
    @modified.id = 442
    @modified.qr = true
    @modified.opCode = Header::IQUERY
    @modified.aa = true
    @modified.tc = true
    @modified.rd = false
    @modified.cd = false
    @modified.ra = true
    @modified.rCode = Header::RCode::FORMAT
    @modified.qdCount = 1
    @modified.anCount = 2
    @modified.nsCount = 3
    @modified.arCount = 3

    @data = @modified.data
    num = [(@data.unpack("n")[0]+1)].pack("n")
    @data[0],@data[1] = num[0], num[1]
    @binary = Header.parse(@data)
    
  end

  def test_simple
    assert_equal(@default.query?, true)
    assert_equal(@default.response?, false)
    assert_equal(@default.opCode, Header::QUERY)
    assert_equal(@default.auth?, false)
    assert_equal(@default.truncated?, false)
    assert_equal(@default.recursive?, true)
    assert_equal(@default.checking?, true)
    assert_equal(@default.verified?, false)
    assert_equal(@default.r_available?, false)
    assert_equal(@default.rCode.code, Header::RCode::NOERROR)
    assert_equal(@default.qdCount, 1)
    assert_equal(@default.anCount, 0)
    assert_equal(@default.nsCount, 0)
    assert_equal(@default.arCount, 0)

    assert_equal(@hash.id, 441)    
    assert_equal(@hash.query?, false)
    assert_equal(@hash.response?, true)
    assert_equal(@hash.opCode, Header::IQUERY)
    assert_equal(@hash.auth?, true)
    assert_equal(@hash.truncated?, true)
    assert_equal(@hash.recursive?, false)
    assert_equal(@hash.checking?, true)
    assert_equal(@hash.verified?, false)
    assert_equal(@hash.r_available?, true)
    assert_equal(@hash.rCode.code, Header::RCode::FORMAT)
    assert_equal(@hash.qdCount, 1)
    assert_equal(@hash.anCount, 2)
    assert_equal(@hash.nsCount, 3)
    assert_equal(@hash.arCount, 3)
    
    assert_equal(@modified.id, 442)    
    assert_equal(@modified.query?, false)
    assert_equal(@modified.response?, true)
    assert_equal(@modified.opCode, Header::IQUERY)
    assert_equal(@modified.auth?, true)
    assert_equal(@modified.truncated?, true)
    assert_equal(@modified.recursive?, false)
    assert_equal(@modified.checking?, true)
    assert_equal(@modified.verified?, false)
    assert_equal(@modified.r_available?, true)
    assert_equal(@modified.rCode.code, Header::RCode::FORMAT)
    assert_equal(@modified.qdCount, 1)
    assert_equal(@modified.anCount, 2)
    assert_equal(@modified.nsCount, 3)
    assert_equal(@modified.arCount, 3)
    
    assert_equal(@binary.data, @data)

    assert_equal(@binary.id, 443)    
    assert_equal(@binary.query?, false)
    assert_equal(@binary.response?, true)
    assert_equal(@binary.opCode, Header::IQUERY)
    assert_equal(@binary.auth?, true)
    assert_equal(@binary.truncated?, true)
    assert_equal(@binary.recursive?, false)
    assert_equal(@binary.checking?, true)
    assert_equal(@binary.verified?, false)
    assert_equal(@binary.r_available?, true)
    assert_equal(@binary.rCode.code, Header::RCode::FORMAT)
    assert_equal(@binary.qdCount, 1)
    assert_equal(@binary.anCount, 2)
    assert_equal(@binary.nsCount, 3)
    assert_equal(@binary.arCount, 3)
    
    assert_raises(ArgumentError) do
      Header.new(Array.new)
    end
    assert_raises(ArgumentError) do
      Header.parse(Array.new)
    end
    assert_raises(ArgumentError) do
      Header.parse("aa")
    end
    assert_raises(ArgumentError) do
      @default.id = 1000000
    end
    assert_raises(ArgumentError) do
      @default.qr=2
    end
    assert_raises(Header::WrongOpcodeError) do
      @default.opCode=4
    end
    assert_raises(ArgumentError) do
      @default.aa=2
    end
    assert_raises(ArgumentError) do
      @default.tc=2
    end
    assert_raises(Header::WrongRecursiveError) do
      @default.recursive=2
    end
    assert_raises(ArgumentError) do
      @default.ra=2
    end
    assert_raises(ArgumentError) do
      @default.cd=2
    end
    assert_raises(ArgumentError) do
      @default.ad=2
    end
    assert_raises(ArgumentError) do
      @default.rCode=46
    end
    assert_raises(Header::WrongCountError) do
      @default.qdCount=100000
    end
    assert_raises(Header::WrongCountError) do
      @default.anCount=100000
    end
    assert_raises(Header::WrongCountError) do
      @default.nsCount=100000
    end
    assert_raises(Header::WrongCountError) do
      @default.arCount=100000
    end
  end    

end
    
