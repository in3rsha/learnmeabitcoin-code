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

puts base58_encode('00662ad25db00e7bb38bc04831ae48b4b446d1269817d515b6')
