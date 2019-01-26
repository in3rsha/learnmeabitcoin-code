#!/usr/bin/env ruby
require 'digest'

module Utils
  def hash160(data)
    binary = [data].pack("H*") # Convert to binary before hashing
    sha256 = Digest::SHA256.digest(binary)
    ripemd160 = Digest::RMD160.digest(sha256)
    hash160 = ripemd160.unpack("H*").join # Convert back from binary to hexadecimal
    return hash160
  end
end

class Script
  attr_reader :asm, :hex, :type

  def initialize(data)
    if data =~ /^\S*$/                    # hex (no whitespaces, so probably hex script)
      @hex, @asm = data, hex_to_asm(data)
    else                                  # asm
      @hex, @asm = asm_to_hex(data), data
    end

    @type = get_type(@asm)
  end

  def hex_to_asm(hex)
    asm = []
    bytes = hex.scan(/../)

    while byte = bytes.shift
      int = byte.to_i(16)

      if int > 0 && int < 0x4b
        data = bytes.shift(int).join
        asm << data
      else
        asm << OPCODES.get_opcode(byte) # Get OPCODE from hex value (checks list of constants)
      end
    end

    return asm.join(' ')
  end

  def asm_to_hex(asm)
    hex = ''
    pieces = asm.split

    while piece = pieces.shift
      begin
        hex << OPCODES.const_get(piece) # Get hex value for OPCODE
      rescue
        push = (piece.length / 2).to_s(16) # Number of bytes to push
        hex << push + piece # Just add the bytes if it is not an OPCODE constant
      end
    end

    return hex
  end

  def get_type(asm)
    asm = asm.split

    if asm.length == 2 && asm[1] == 'OP_CHECKSIG'
      :p2pk
    elsif asm.length == 5 && asm[0] == 'OP_DUP' && asm[1] == 'OP_HASH160' && asm[3] == 'OP_EQUALVERIFY' && asm[4] == 'OP_CHECKSIG'
      :p2pkh
    elsif asm.length == 3 && asm[0] == 'OP_HASH160' && asm[2] == 'OP_EQUAL'
      :p2sh
    elsif asm[0] =~ /OP_[0-9]*/ && asm[-2] =~ /OP_[0-9]*/ && asm[-1] == 'OP_CHECKMULTISIG'
      :p2ms
    elsif asm.length == 2 && asm[0] == 'OP_RETURN'
      :return
    else
      :unknown
    end
  end

  # Takes a lockingscript (and optional unlockingscript) object
  def Script.run(*scripts) # OP_CHECKSIG needs the hash of the thing to sign for it to work

    # 0. If locking script given and it's P2SH, run specific run_p2sh validation for it
    return Script.run_p2sh(scripts) if scripts.size > 1 && scripts[1].type == :p2sh

    # 1. Combine all the scripts we have been given in to a single script
    script = scripts.map {|script| script.asm.split }.flatten

    # 2. Run through OPCODES and execute each using a Stack
    stack = []

    yield(script, stack) if block_given? # Display

    while opcode = script.shift                    # Take each element of the script array
      opcode_method = (opcode).to_sym              # Convert to symbol (so we can send the method to the opcodes module): OP_DUP -> :OP_DUP
      if OPCODES.respond_to?(opcode_method)        # If we have written the rules for an OP_CODE
        stack = OPCODES.send(opcode_method, stack) # Call it: OPCODES.OP_DUP
      else
        stack << opcode                            # If not opcode, just add data to the stack (anything that is not an OP_CODE method)
      end

      yield(script, stack) if block_given? # Display (Can give a block to this method to display stuff.)
    end

    # 2. Return the final stack
    stack
  end

  # P2SH scripts have special validation rules compared to other scripts (they contain an inner script that has to be run secondary)
  def Script.run_p2sh(scripts)

    # PRIMARY
    # -------
    # 0. Get each script (unlocking + locking)
    unlockingscript = scripts[0]
    lockingscript = scripts[1]

    # 0. Create complete script from these two scripts
    script = Script.new(unlockingscript.hex + lockingscript.hex)

    # 1. Create a stack from the unlocking script
    stack = Script.run(unlockingscript)

    # 2. Copy this stack for later
    stackcopy = stack.dup

    # 3. Run the script as normal
    stack = Script.run(script) { |script, stack| # Script.run gives the script and stack to this block of code
      system('clear')
      puts "Script: #{script.inspect}"
      puts
      puts stack.reverse # Want to see the top stack item at the top
      gets
    }

    # SECONDARY
    # ---------
    # 4. Check primary script was valid
    if Script.validate(stack)

      # i. Top item on initial stack was the inner script (redeemscript)
      pop = stackcopy.pop
      redeemscript = Script.new(pop)

      # ii. Create new script using the redeem script as the locking script
      script = Script.new(unlockingscript.hex + redeemscript.hex)

      # iii. Run this secondary script
      stack2 = Script.run(script) { |script, stack| #Script.run gives the script and stack to this block of code
        system('clear')
        puts "Script: #{script.inspect}"
        puts
        puts stack.reverse # Want to see the top stack item at the top
        gets
      }

      return stack2

    end

  end

  def Script.validate(stack)
    # If stack is empty or top element is OP_TRUE or top element is an OP greater than 0
    if not stack.empty? and (stack.pop == 'OP_TRUE' or stack.pop.sub('OP_', '').to_i > 0)
      true
    else
      false
    end
  end


  module OPCODES
    require 'ecdsa'
    extend Utils # hash160

    # OPCODE         hex
    OP_0           = '00'
    OP_1           = '51'
    OP_2           = '52'
    OP_3           = '53'
    OP_4           = '54'
    OP_5           = '55'
    OP_6           = '56'
    OP_7           = '57'
    OP_8           = '58'
    OP_9           = '59'
    OP_10          = '5a'
    OP_11          = '5b'
    OP_12          = '5c'
    OP_13          = '5d'
    OP_14          = '5e'
    OP_15          = '5f'
    OP_16          = '60'
    OP_RETURN      = '6a'
    OP_DUP         = '76'
    OP_EQUAL       = '87'
    OP_EQUALVERIFY = '88'
    OP_CHECKSIG    = 'ac'
    OP_CHECKMULTISIG = 'ae'
    OP_HASH160     = 'a9'

    # Get an OPCODE name from list of constants (used in hex_to_asm)
    def self.get_opcode(hex)
      self.constants.select {|constant| hex == self.const_get(constant) }
    end


    # OPCODE Logic (execute on a stack)
    def self.OP_DUP(stack)
      raise "There is nothing on the stack that we can pop off to duplicate." if stack.empty?
      pop = stack.pop
      stack << pop << pop
    end

    def self.OP_HASH160(stack)
      raise "There is nothing on the stack that we can hash160." if stack.empty?
      pop = stack.pop
      stack << hash160(pop)
    end

    def self.OP_EQUAL(stack)
      pop = stack.pop(2)
      raise "Last 2 stack items are not equal: #{pop}" if pop.uniq.size != 1 # If these two items are not the same
      stack << 'OP_TRUE'
    end

    def self.OP_EQUALVERIFY(stack)
      pop = stack.pop(2)
      raise "Last 2 stack items are not equal: #{pop}" if pop.uniq.size != 1 # If these two items are not the same
      stack
    end

    def self.OP_CHECKSIG(stack)
      raise "There is no public key on the stack that we can pop off." if stack.empty?
      publickey = stack.pop

      raise "There is no signature on the stack that we can pop off." if stack.empty?
      signature = stack.pop

      # Note: This CHECKSIG does not actually validate a signature against a public key
      # If it did, you would also need to know the current transaction data (the thing being signed) and the scriptPubKey of this input
      stack << 'OP_TRUE'
    end

    def self.OP_CHECKMULTISIG(stack)
      m = stack.pop.sub('OP_', '').to_i # e.g. OP_3 to 2
      raise "Not enough signatures on the stack." if stack.size < m
      signatures = stack.pop(m)

      n = stack.pop.sub('OP_', '').to_i
      raise "Not enough public keys on the bottom of the stack." if stack.size < n + 1
      publickeys = stack.pop(n + 1) # Off by one error in bitcoin implementation

      # Note: This CHECKMUTLISIG does not actually validate
      stack << 'OP_TRUE'
    end

    def self.OP_RETURN(stack)
      raise "Script is invalid. (OP_RETURN always invalidates a script.)"
    end

  end

end


# TUI
system('clear')

print "Locking Script: ";
lockingscript = gets.chomp
lockingscript = Script.new(lockingscript)
puts lockingscript.type
gets
system('clear')

puts "Locking Script: " + lockingscript.asm
print "Unlocking Script: ";
unlockingscript = gets.chomp
unlockingscript = Script.new(unlockingscript)
system('clear')

puts "Locking Script: " + lockingscript.asm
puts "Unlocking Script: " + unlockingscript.asm;
puts

print "Run this script? (y/n): "; yn = gets.chomp
if yn == '' || 'y'
  system('clear')

  stack = Script.run(unlockingscript, lockingscript) { |script, stack| #Script.run gives the script and stack to this block of code
    system('clear')
    puts "Script: #{script.inspect}"
    puts
    puts stack.reverse # Want to see the top stack item at the top
    gets
  }

  if Script.validate(stack)
    puts "This is a valid script!"
  else
    puts "This is not a valid script."
  end
end


# EXAMPLE SCRIPTS (Standard)
# ---------------

# p2pk: 4104240ac91558e66c0628693cee5f5120d43caf73cad8586f9f56a447cc6b926520d2b3b259874e5d79dfb4b9aff3405a10cbce47ee820e0824dc7004d5bbcea86fac
# p2pk (unlock): 4730440220277c967dda11986e06e508235006b7e83bc27a1cb0ffaa0d97a543e178199b6a022040d4f8f17865e45de9ca7bcfe3ee2228e175cfcb4468b7650f09b534d3f71f4401

# p2pkh: 76a91491ef7f43180d71d61ca3870a1b0445c116efa78088ac
# p2pkh (unlock):

# p2sh: a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87
# p2sh (unlock): 00483045022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf88302200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b79001455141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae

# p2ms: 5141204e00003bf2a106de6a91d6b7d3d8f067e70fd40ab0bd7c12f278c35eba8e16e1cd73e5d9871f1f2a027659bce210737856849248260a58e973a9a37a6fbca6354100d8fbd53efe72e1fd664c935e929b2c41b050f5813c93b2d3e8128b3c0e283362002e687c41785947241b3c2523bb9143c80ee82d50867259af4b47a332a8a0aa412f3258f7717826ed1e585af67f5712abe35fb533513d929087cbb364532da3340e377bb156f25c8ee3e2cabb986158eaefe7c3adb4f4a88771440947b1b0c1a34053ae

# return: 6a24aa21a9edcdcb2e39372f6650e4f9d730c34318cc4f0c8d2b9ba3ec2a8b9c74350f7b3044
