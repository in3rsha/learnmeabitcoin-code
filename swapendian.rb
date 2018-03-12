#!/usr/bin/ruby

def swapendian(hex)
	# 1. Reverse the string
	reverse = hex.reverse
	
	# 2. Get every 2 characters from the string in to an array.
	bytes = reverse.scan(/../)

	# 3. Run through each element of the array and reverse it. (map is like each but actually returns the work)
	reverse_bytes = bytes.map {|byte| byte.reverse}

	# 4. Join the array in to a string.
	result = reverse_bytes.join('')

	return result
end

hex = ARGV[0] || STDIN.gets.chomp
puts swapendian(hex)

=begin Note: In one line...
	hex.reverse.scan(/../) {|byte| byte.reverse}
or
	hex.scan(/../).reverse.join('')
=end
