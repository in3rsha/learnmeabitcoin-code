# Checksums are used when creating addresses
def checksum(hex)
  hash = hash256(hex) # Hash the data through SHA256 twice
  return hash[0...8]  # Return the first 4 bytes (8 characters)
end

puts checksum('00662ad25db00e7bb38bc04831ae48b4b446d12698')
