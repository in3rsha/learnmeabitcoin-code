#!/usr/bin/env ruby

def hexdec(hex)
	dec = hex.to_i(16)
	return dec
end

hex = ARGV[0] || STDIN.gets.chomp
puts hexdec(hex)
