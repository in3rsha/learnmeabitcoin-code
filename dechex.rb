#!/usr/bin/ruby

def dechex(dec)
	dec = dec.to_i		# convert argument to integer
	hex = dec.to_s(16)	# convert integer to hex string
	return hex
end

dec = ARGV[0] || STDIN.gets.chomp
puts dechex(dec)
