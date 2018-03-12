#!/usr/bin/env ruby

require 'ecdsa'        # Elliptic curve library needed to sign transaction data using a private key (gem install ecdsa)
require 'securerandom' # need a random number when using the elliptic curve to create a signature

# Handy functions for getting data in to the correct format
module Utils
  def reversebytes(hex)
    return hex.to_s.scan(/../).reverse.join
  end

  def dechex(dec)
    return dec.to_i.to_s(16)
  end

  # Add padding to create a fixed-size field (e.g. 4 => 00000004)
  def field(field, size=4)
    return field.to_s.rjust(size*2, '0')
  end

  # A compact format for storing the upcoming number of bytes for a variable-length piece of data (e.g. a signature)
  def varint(i)
    if (i <= 252)
      varint = field(dechex(i), 1)
    elsif (i > 252 && i <= 65535)
      varint = 'fd' + field(dechex(i), 2)
    elsif (i > 65535  && i <= 4294967295)
      varint = 'fe' + field(dechex(i), 4)
    elsif (i > 4294967295 && i <= 18446744073709551615)
      varint = 'ff' + field(dechex(i), 8)
    end

    return varint
  end

  # scriptPubKey: Need to convert addresses we are given back in to the hash160(publickey) to create the lock
  def base58_to_int(base58_val)
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    int_val, base = 0, alpha.size
    base58_val.reverse.each_char.with_index do |char,index|
      raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)
      int_val += char_index*(base**index)
    end
    int_val
  end

  def decode_base58(base58_val)
    s = base58_to_int(base58_val).to_s(16); s = (s.bytesize.odd? ? '0'+s : s)
    s = '' if s == '00'
    leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
    s = ("00"*leading_zero_bytes) + s  if leading_zero_bytes > 0
    s
  end

  # scriptSig: The publickey is needed along with the signature. We can get this from the privatekey that has been provided.
  def private_to_public(privatekey)
    group = ECDSA::Group::Secp256k1
    publickey = group.generator.multiply_by_scalar(privatekey.to_i(16))

    # Instead of using both x and y co-ordinates, just use the x co-ordinate and whether y is even/odd
    prefix = publickey.y % 2 == 0 ? '02' : '03' # even = 02, odd = 03

    # Add the prefix to the x co-ordinate
    publickey = prefix + publickey.x.to_s(16)

    return publickey
  end

  # scriptSig: You need to hash the transaction data to create the message. The message goes in to the elliptic curve
  def hash256(hex)
    binary = [hex].pack("H*")
    hash1 = Digest::SHA256.digest(binary)
    hash2 = Digest::SHA256.digest(hash1)
    result = hash2.unpack("H*")[0]
    return result
  end

end

class Transaction
  include Utils

  attr_accessor :version
  attr_accessor :inputs
  attr_accessor :outputs
  attr_accessor :locktime

  def initialize(version=nil, locktime=nil)
    @version = version
    @inputs = []
    @outputs = []
    @locktime = locktime
  end

  def add_input(txid, vout)
    @inputs << Input.new(txid, vout)
  end

  def add_output(value, address)
    @outputs << Output.new(value, address)
  end

  def sign(i, privatekey, placeholder)

    hashtype = '01000000'
    sighashtype = '01'

    # Clone current object (and all sub-objects) so that we can create a signature without having to modify the transaction data.
    tx = Marshal.load(Marshal.dump(self)) # Uses Marshal to create a "deep clone". Unfortunately self.clone only clones current object.

    # Remove all signatures from the transaction, and set the placeholder for the Input we want to sign
    tx.inputs.each.with_index do |input, vin|
      if vin == i
        input.scriptSig = placeholder
      else
        input.scriptSig = ''
      end
    end

    # Prepare the elliptic curve data
    group = ECDSA::Group::Secp256k1      # secp256k1 is the name of the particular curve bitcoin uses
    privatekey = privatekey.to_i(16)     # must be integer

    # Add hashtype to transaction data, then hash it. This is the message we are signing.
    message = hash256(tx.serialize + hashtype)
    message = [message].pack("H*")  # must be binary

    # Sign the transaction data with the privatekey using the elliptic curve
    signature = nil
    while signature.nil?
      temp_key = 1 + SecureRandom.random_number(group.order - 1)   # Uses a random number for security
      signature = ECDSA.sign(group, privatekey, message, temp_key)
    end

    r = signature.r # The signature has an r value and an s value
    s = signature.s

    # The s value must be less than (N/2). N is the number of points on the curve (also known as "order").
    if s > group.order / 2
      # s = group.order - s  # Apparently, if s is greater than N/2, then you can set s = N-s
      raise "Signature S value is too high!"
    end
    # This prevents transaction malleability.

    # Convert signature to DER encoding
    ## Manually create DER encoding: <30> <varint all> <02> <varint R> <   R   > <02> <varint S> <   S   >
    ### Couldn't get this working perfectly
     #r = r.to_s(16) # Convert to hexadecimal
     #s = s.to_s(16)

     #r = (r.length % 2 == 0 ? r : '0' + r) # Add a zero to the start if hex string is not an even length
     #s = (s.length % 2 == 0 ? s : '0' + s)

     #rs = '02' + varint(r.length/2) + r + '02' + varint(s.length/2) + s
     #der = '30' + varint(rs.length/2) + rs

    ## Create DER encoding using library (this works fine)
    der = ECDSA::Format::SignatureDerString.encode(signature) # this is in binary
    der = der.unpack("H*").join # unpack returns an array, so need to .join it back in to a string

    # Add sighashtype to the signature
    signatureder = der + sighashtype

    # Get the publickey from the privatekey, because it's needed along with the signature in the scriptSig to unlock the input
    publickey = private_to_public(privatekey.to_s(16))

    # Build the scriptSig
    # <varint> {signature} <varint> {publickey}
    scriptSig = varint(signatureder.length/2) + signatureder + varint(publickey.length/2) + publickey

    # Set the scripSig for this input
    inputs[i].scriptSig = scriptSig
  end

  def serialize()
    serialized = ''

    if (version != nil)
      serialized += reversebytes(field(dechex(@version), 4))       # version
    end

    if (@inputs.count > 0)
      serialized += varint(@inputs.count)                          # input count
      @inputs.each { |input| serialized += input.serialize() }     # inputs
    end

    if (@outputs.count > 0)
      serialized += varint(@outputs.count)                         # output count
      @outputs.each { |output| serialized += output.serialize() }  # outputs
    end

    if (locktime != nil)
      serialized += reversebytes(field(dechex(@locktime), 4))      # locktime
    end

    return serialized
  end

end

class Input
  include Utils

  attr_accessor :scriptSig

  def initialize(txid, vout, scriptSig='', sequence='ffffffff')
    @txid = txid
    @vout = vout
    @scriptSig = scriptSig
    @sequence = sequence
  end

  def serialize()
    return reversebytes(@txid) + reversebytes(field(dechex(@vout))) + varint(@scriptSig.length/2) + @scriptSig + @sequence
  end

end

class Output
  include Utils

  def initialize(value, address)
    @value = value
    @address = address
    @scriptPubKey = create_scriptPubKey(address)
  end

  def create_scriptPubKey(address)
    # Decode the address to get the hashed version of the publickey (we need this to create the lock)
    hash160 = decode_base58(address)

    # Remove the prefix and checksum from sides to get the 20-byte hashed publickey on its own. e.g: [00]xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx[9fb82a36]
    hash160 = hash160[2,40]

    # Put the hashed publickey in to a typical scriptPubKey (by using the publickey, it will be locked to the address we were given)
    scriptPubKey = '76a914' + hash160 + '88ac' # OP_DUP OP_HASH160 hash160 OP_EQUALVERIFY OP_CHECKSIG
  end

  def serialize()
    return reversebytes(field(dechex(@value), 8)) + varint(@scriptPubKey.length/2) + @scriptPubKey
  end

end


# Terminal User Interface - Build the transaction on the command line.
# -----------------------

system('clear')
tx = Transaction.new()


# 1. Set Version number
system('clear')
puts "Transaction Builder"; puts "-------------------"; puts

print "Version (1): ";
version = gets
tx.version = version


# 2. Gather Inputs
system('clear')
puts "Transaction Builder"; puts "-------------------"; puts
puts tx.serialize; puts

puts "Inputs (txid vout):"

i = 0
loop do
  print "  #{i}: "
  reference = gets.chomp    # txid vout
  break if reference.empty?

  txid = reference.split[0]
  vout = reference.split[1]

  tx.add_input(txid, vout)

  i = i + 1
end


# 3. Gather Outputs
system('clear')
puts "Transaction Builder"; puts "-------------------"; puts
puts tx.serialize; puts

puts "Outputs (value address):"

i = 0
loop do
  print "  #{i}: "
  create = gets.chomp    # txid vout
  break if create.empty?

  value = create.split[0]
  address = create.split[1]

  tx.add_output(value, address)

  i = i + 1
end


# 4. Set Locktime
system('clear')
puts "Transaction Builder"; puts "-------------------"; puts
puts tx.serialize; puts

print "Locktime (0): ";
locktime = gets
tx.locktime = locktime


# 5. Now that we have built the full transaction structure, time to sign the inputs so that the transaction is valid.
system('clear')
puts "Transaction Builder"; puts "-------------------"; puts
puts tx.serialize; puts

puts "Sign Inputs (privatekey, lock):"
tx.inputs.each_with_index do |input, i|
  print "  #{i}: "
  details = gets.chomp    # txid vout
  break if details.empty?

    privatekey = details.split[0]
    placeholder = details.split[1]

  begin
    tx.sign(i, privatekey, placeholder)
  rescue
    puts "S value too high, trying again..."
    sleep 1
    retry
  end

end


# Show the completed transaction data
system('clear')
puts "Transaction Builder"; puts "-------------------"; puts
puts tx.serialize; puts
puts "Your transaction, Ma'am."


# Testing
# -------

# tx = Transaction.new(1,0)
# tx.add_input('2ab8300fdb32cc24231efd6f1586aff089f70416ad1b30f23511d91d366427e8', 0)
# tx.add_output(575077, '15kmxGrv4jdCybGq5i5S5oiczMB6VBrWnj') # 296900

#        #i,  privatekey,                                                         placeholder (the original scriptPubKey)
# tx.sign(0, 'privatekey', 'scriptPubKey')

# puts tx.serialize
