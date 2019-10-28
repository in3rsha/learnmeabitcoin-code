# Learn Me A Bitcoin Code

Small, educational snippets of code to help you to understand and work with Bitcoin.

## Command Line Tools

* [hexdec.rb](hexdec.rb) - Convert hexadecimal to decimal
* [dechex.rb](dechex.rb) - Convert decimal to [hexadecimal](http://learnmeabitcoin.com/guide/hexadecimal)
* [swapendian.rb](swapendian.rb) - Reverse the [byte order](http://learnmeabitcoin.com/guide/little-endian) of a string 
* [hash256.rb](hash256.rb) - The double-SHA256 hashing that Bitcoin uses
<!--
* [merkleroot.rb](merkleroot.rb) - Create a [merkle root](http://learnmeabitcoin.com/guide/merkle-root) from a list of [TXID](http://learnmeabitcoin.com/guide/txid)s
-->

## Learning

* [miningsimulator.rb](miningsimulator.rb) - Hashes a [block header](https://learnmeabitcoin.com/guide/block-header) until it gets a hash below the [target](https://learnmeabitcoin.com/guide/target).

<img src="images/miningsimulator.gif" style="margin:0 0 0 36px" />

* [transactionbuilder.rb](transactionbuilder.rb) - Build a transaction from scratch, showing the [transaction data](https://learnmeabitcoin.com/guide/transaction-data) as you go.

* [keygenerator.rb](keygenerator.rb) - Create a set of keys ([Private Key](https://learnmeabitcoin.com/guide/private-key), [Public Key](https://learnmeabitcoin.com/guide/public-key), Address) for sending and receiving bitcoin.

* [scriptdecoder.rb](keygenerator.rb) - Decode and run [script](https://learnmeabitcoin.com/guide/script).
