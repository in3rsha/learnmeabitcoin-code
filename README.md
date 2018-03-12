# LearnMeABitcoin Code

Small, educational snippets of code to help you to understand and work with Bitcoin.

## Command Line Tools

* [hexdec.rb](hexdec.rb) - Convert hexadecimal to decimal
* [dechex.rb](dechex.rb) - Convert decimal to [hexadecimal](http://learnmeabitcoin.com/glossary/hexadecimal)
* [swapendian.rb](swapendian.rb) - Reverse the [byte order](http://learnmeabitcoin.com/glossary/little-endian) of a string 
* [hash256.rb](hash256.rb) - The double-SHA256 hashing that Bitcoin uses
* [merkleroot.php](merkleroot.php) - Create a [merkle root](http://learnmeabitcoin.com/glossary/merkle-root) from a list of [TXID](http://learnmeabitcoin.com/glossary/txid)s

## Learning

* [miningsimulator.rb](miningsimulator.rb) - Hashes a [block header](http://learnmeabitcoin.com/glossary/block-header) until it gets a hash below the [target](http://learnmeabitcoin.com/glossary/target).

<img src="images/miningsimulator.gif" style="margin:0 0 0 36px" />

* [transactionbuilder.rb](transactionbuilder.rb) - Build a transaction from scratch, showing the [transaction data](http://learnmeabitcoin.com/glossary/transaction-data) as you go.

* [keygenerator.rb](keygenerator.rb) - Create a set of keys ([Private Key](http://learnmeabitcoin.com/glossary/private-key), [Public Key](http://learnmeabitcoin.com/glossary/public-key), Address) for sending and receiving bitcoin.
