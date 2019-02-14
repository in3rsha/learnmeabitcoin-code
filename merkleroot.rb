require 'digest' # Need this for the SHA256 hash function

# Hash function used in the merkle root function (and in bitcoin in general)
def hash256(hex)
    binary = [hex].pack("H*")
    hash1 = Digest::SHA256.digest(binary)
    hash2 = Digest::SHA256.digest(hash1)
    result = hash2.unpack("H*")[0]
    return result
end

def merkleroot(txids)
  # 0. Keep an array of results for each level of hashing
  result = []

  # 1. Split up array in to pairs
  txids.each_slice(2) do |one, two|
    # 2. Concatenate each pair (or concatenate with itself if not a pair)
    if (two)
      concat = one + two
    else
      concat = one + one
    end

    # 3. Hash the concatenated pair and add to results array
    result << hash256(concat)
  end

  # Recursion: Exit Condition - Stop recursion when we have one final hash result.
  if result.length == 1
    # Convert the result to a string and return it
    return result.join('')
  end

  # Recursion: Do the same thing again for the array of hashed pairs.
  merkleroot(result)
end


# Test (e.g. block 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506)
txids = [
  "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
  "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
  "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
  "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
]

txids = txids.map {|x| x.scan(/../).reverse.join('') } # TXIDs must be in little endian
result = merkleroot(txids) # The result is in little endian, so lets convert it back to big endian...
puts result.scan(/../).reverse.join('') # f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766
