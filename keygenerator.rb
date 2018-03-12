require 'securerandom' # Secure Random Number Generator
require 'ecdsa'        # Elliptic Curve
require 'digest'       # Hash Functions

class Keys
  attr_reader :private, :wif, :public, :hash160, :address

  def initialize(privatekey=nil)
    @private = privatekey || generate_private
    @wif     = private_to_wif(@private)
    @public  = private_to_public(@private)
    @hash160 = public_to_hash160(@public)
    @address = hash160_to_address(@hash160)
  end

  def generate_private
    begin
      privatekey = SecureRandom.hex(32) # Generate a random 32-byte (256 bit) hexadecimal number
      max = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 # = N (The order of the elliptic curve we are using)
      raise "Private Key too big" if privatekey.to_i(16) > max
    rescue
      puts "Generating another private key. Last one was greater than the order of the curve."
      retry
    end

    return privatekey
  end

  def private_to_wif(privatekey, compress=true, mainnet=true) # Wallet Import Format
    flag    = compress ? '01' : ''  # Append nothing if the corresponding public key is going to be uncompressed
    version = mainnet ? '80' : 'EF'

    check = checksum(version + privatekey + flag)
    wif = base58_encode(version + privatekey + flag + check)

    return wif
  end

  def private_to_public(privatekey, compress=true)
    # Elliptic Curve Multiplication
    group = ECDSA::Group::Secp256k1 # Select the curve used in Bitcoin
    point = group.generator.multiply_by_scalar(privatekey.to_i(16)) # Multiply by integer (not hex)

    if compress
      # Instead of using both x and y co-ordinates, just use the x co-ordinate and whether y is even/odd
      prefix = point.y % 2 == 0 ? '02' : '03' # even = 02, odd = 03
      # Add the prefix to the x co-ordinate
      publickey = prefix + byte32(point.x.to_s(16)) # Make sure each co-ordinate is a full 32 bytes when converting to hex! (i.e. Don't forget leading zeros)
    else
      prefix = '04' # uncompressed public key
      publickey = prefix + byte32(point.x.to_s(16)) + byte32(point.y.to_s(16))
    end

    return publickey
  end

  def public_to_hash160(publickey)
    binary = [publickey].pack("H*") # Convert to binary before hashing
    sha256 = Digest::SHA256.digest(binary)
    ripemd160 = Digest::RMD160.digest(sha256)

    hash160 = ripemd160.unpack("H*").join # Convert back from binary to hexadecimal
    return hash160
  end

  def hash160_to_address(hash160, type=:p2pkh)
    # https://en.bitcoin.it/wiki/List_of_address_prefixes
    prefixes = {
      p2pkh: '00',         # 1address - For standard bitcoin addresses
      p2sh:  '05',         # 3address - For sending to an address that requires multiple signatures (multisig)
      p2pkh_testnet: '6F', # (m/n)address
      p2sh_testnet:  'C4'  # 2address
    }

    prefix = prefixes[type]
    checksum = checksum(prefix + hash160)
    address = base58_encode(prefix + hash160 + checksum)

    return address
  end


  # Key Utils
  # ---------

  # This double-hashing is used all over when hashing in Bitcoin, but used here to create a checksum
  def hash256(hex)
    binary = [hex].pack("H*")
    hash1 = Digest::SHA256.digest(binary)
    hash2 = Digest::SHA256.digest(hash1)
    return hash2.unpack("H*").join
  end

  # Checksums are used when creating an address
  def checksum(hex)
    hash = hash256(hex) # Hash the data through SHA256 twice
    return hash[0...8]  # Return the first 4 bytes (8 characters)
  end

  # Base58 is used when converting from a hash160 to an address
  def base58_encode(hex)
    @chars = %w[
      1 2 3 4 5 6 7 8 9
    A B C D E F G H   J K L M N   P Q R S T U V W X Y Z
    a b c d e f g h i j k   m n o p q r s t u v w x y z
]
    @base = @chars.length

    i = hex.to_i(16)
    buffer = String.new

    while i > 0
      remainder = i % @base
      i = i / @base
      buffer = @chars[remainder] + buffer
    end

    #! Is it just the 00, or does 05 get converted to 3, etc.
    # add '1's to the start based on number of leading bytes of zeros
    leading_zero_bytes = (hex.match(/^([0]+)/) ? $1 : '').size / 2

    ("1"*leading_zero_bytes) + buffer
  end

  # Add zero padding to create full 32-byte keys
  def byte32(data, size=32)
    return data.to_s.rjust(size*2, '0') # Add zeros to the left
  end
end


# Terminal User Interface
privatekey = Digest::SHA256.hexdigest('learnmeabitcoin') # Create your own private key by hashing some text. RISKY!

keys = Keys.new # Initialize with your own private key if you want. Otherwise, it will generate a new set.
puts "private: " + keys.private
#puts "  wif:   " + keys.wif
puts "public:  " + keys.public
puts "hash160: " + keys.hash160
puts "address: " + keys.address
