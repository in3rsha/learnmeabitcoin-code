#!/usr/bin/env ruby
require 'digest/sha2' # This library gives us the SHA256 hash function
system("clear")       # Clear the terminal screen before we start

# You could tidy up this script by putting these utility functions in their own utils.rb file and requiring them in by uncommenting the the line below
# require_relative 'utils' 
class String
  
  def hash256
    binary = [self].pack("H*")
    hash1 = Digest::SHA256.digest(binary)
    hash2 = Digest::SHA256.hexdigest(hash1)
    return hash2
  end

  def field(size)
    bytes = size * 2
    self.rjust(bytes, '0')
  end

  def reversebytes
    self.scan(/../).reverse.join
  end

  def hex
    self.to_i.to_s(16)
  end

  def dec
    self.to_i(16)
  end
  
end


# Settings
target = '0000000000006a93b30000000000000000000000000000000000000000000000'

# Block Header
version    = '1'
prevblock  = '0000000000000b60bc96a44724fd72daf9b92cf8ad00510b5224c6253ac40095'
merkleroot = '0e60651a9934e8f0decd1c5fde39309e48fca0cd1c84a21ddfde95033762d86c'
time       = '1305200806'  # 2011-05-12 12:46:46 +0100
bits       = '1a6a93b3'
nonce      = 0             # 2436437219

header = version.hex.field(4).reversebytes + prevblock.reversebytes + merkleroot.reversebytes + time.hex.field(4).reversebytes + bits.reversebytes

# Miner
def mine(header, nonce, target)
  loop do
    attempt = header + nonce.to_s.hex.field(4).reversebytes
    blockhash = attempt.hash256.reversebytes

    puts "#{nonce}: #{blockhash}"

    if blockhash.dec < target.dec
      puts "Block Hash is below the Target! This block has been mined!"
      break
    end

    nonce += 1
    
	# Uncomment the line below to slow down the hashing
	#sleep(0.1)

  end
end

# Simulator
puts 'Mining Simulator'
STDIN.gets

puts <<-TXS
1. Get Transactions
-------------------
transactions: 13
TXS
STDIN.gets

puts <<-HEADER
2. Block
--------
version:    #{version}
prevblock:  #{prevblock}
merkleroot: #{merkleroot}
time:       #{time} (#{Time.at(time.to_i)})
bits:       #{bits}
nonce:      ________
HEADER
STDIN.gets

puts header + '________';
STDIN.gets

puts <<-TARGET
3. Target
--------- 
#{target}
TARGET
STDIN.gets

mine(header, nonce, target)
