#!/usr/bin/env ruby

require 'digest'

def hash256(hex)
	# 1. Convert hex string to array, and pack in to binary
	binary = [hex].pack("H*")

	# 2. Hash the binary value (returning binary)
	hash1 = Digest::SHA256.digest(binary)

	# 3. Hash it again (returning hex)
	hash2 = Digest::SHA256.digest(hash1)

	# 4. Convert back to hex (must unpack as array)
	result = hash2.unpack("H*")[0]

	return result
end

hex = ARGV[0] || STDIN.gets.chomp
puts hash256(hex)
