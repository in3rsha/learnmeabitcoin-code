#!/usr/bin/php
<?php

// Swap Endian function
function swapendian($data) {
    return implode('', array_reverse(str_split($data, 2)));
}

// Merkle Root Function
function merklerootbinary($txids) {
 
	// Stop recursion if there is only one hash value left, because that's the merkle root.
	if (count($txids) == 1) {
		$merkleroot = $txids[0];
		return $merkleroot;
	}
 
	else {
 
		// Create the new array of hashes		
		while (count($txids) > 0) {
 
			if (count($txids) >= 2) {
				// Get first two
				$pair_first = $txids[0];
				$pair_second = $txids[1];
 
				// Hash them (double SHA256)
				$pair = $pair_first.$pair_second;
				$pairhashes[] = hash('sha256', hash('sha256', $pair, true), true);
 
				// Remove those two from the array
				unset($txids[0]);
				unset($txids[1]);
 
				// Re-set the indexes (the above just nullifies the values) and make a new array without the original first two slots.
				$txids = array_values($txids);
			}
 
			if (count($txids) == 1) {
				// Get the first one twice
				$pair_first = $txids[0];
				$pair_second = $txids[0];
 
				// Hash it with itself (double SHA256)
				$pair = $pair_first.$pair_second;
				$pairhashes[] = hash('sha256', hash('sha256', $pair, true), true);
 
				// Remove it from the array
				unset($txids[0]);
 
				// Re-set the indexes (the above just nullifies the values) and make a new array without the original first two slots.
				$txids = array_values($txids);
			}
 
		}
 
		// Recursion bit. Re-apply this function to the new array of hashes we've just created.
		return merklerootbinary($pairhashes);
 
	}
 
}
 
function merkleroot($txids) {
 
	// Convert txids in to big endian (BE), because that's the format they need to be in to get the merkle root.
	foreach ($txids as $txid) {
		$txidsBE[] = swapendian($txid);
	}
 
	// Now convert each of these txids in to binary, because the hash function wants the binary value, not the hex.
	foreach ($txidsBE as $txidBE) {
		$txidsBEbinary[] = hex2bin($txidBE);
	}
 
	// Work out the merkle root (in binary) using that lovely recursive function above.
	$merkleroot = merklerootbinary($txidsBEbinary);
 
	// Convert the merkle root in to hexadecimal and little-endian, because that's how it's stored in the block header.
	$merkleroot = swapendian(bin2hex($merkleroot));
 
	// Return it :)
	return $merkleroot;
 
}


// Get lines from STDIN
$lines = file('php://stdin');

// Clean up input (remove whitespace and ")
$txids = [];
foreach ($lines as $line) {
    $txids[] = str_replace('"', '', trim($line));
}

// Work out the Merkle Root
$merkleroot = merkleroot($txids);

// Print Result
echo $merkleroot."\n";
