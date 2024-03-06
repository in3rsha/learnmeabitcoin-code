# Learn Me A Bitcoin Code

Small, educational snippets of code to help you to understand and work with Bitcoin.

## Command Line Tools

* [hexdec.rb](hexdec.rb) - Convert hexadecimal to decimal
* [dechex.rb](dechex.rb) - Convert decimal to [hexadecimal](https://learnmeabitcoin.com/technical/general/hexadecimal/)
* [swapendian.rb](swapendian.rb) - Reverse the [byte order](https://learnmeabitcoin.com/technical/general/byte-order/) of a string 
* [hash256.rb](hash256.rb) - The double-SHA256 [hashing](https://learnmeabitcoin.com/technical/cryptography/hash-function/) that Bitcoin uses
<!--
* [merkleroot.rb](merkleroot.rb) - Create a [merkle root](https://learnmeabitcoin.com/technical/block/merkle-root/) from a list of [TXID](https://learnmeabitcoin.com/technical/transaction/input/txid/)s
-->

## Learning

* [miningsimulator.rb](miningsimulator.rb) - Hashes a [block header](https://learnmeabitcoin.com/technical/block/#header) until it gets a hash below the [target](https://learnmeabitcoin.com/technical/mining/target/).

<img src="images/miningsimulator.gif" style="margin:0 0 0 36px" />

* [transactionbuilder.rb](transactionbuilder.rb) - Build a transaction from scratch, showing the [transaction data](https://learnmeabitcoin.com/technical/transaction/) as you go.

* [keygenerator.rb](keygenerator.rb) - Create a set of keys ([Private Key](https://learnmeabitcoin.com/technical/keys/private-key/), [Public Key](https://learnmeabitcoin.com/technical/keys/public-key/), [Address](https://learnmeabitcoin.com/technical/keys/address/)) for sending and receiving bitcoin.

* [scriptdecoder.rb](scriptdecoder.rb) - Decode and run [Script](https://learnmeabitcoin.com/technical/script/).
