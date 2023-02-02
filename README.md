# Cryptographic passphrase encoder for BTC protocol
This program can be used to recover mnemonic sentence for a target address having partially complete unordered word list.

Core functionality of this program is to
- Take an incomplete list of mnemonic words and fill it with all possible combinations of the remaining ones
- For each combination, loop over all permutations of the ordering
- For each permutation, check if the ordering yields a valid mnemonic based on the checksum
- If the mnemonic is valid, generate master private key and master public key
- Follow the BIP32 derivation path to obtain child private and public keys
- Calculate SegWit Pay-To-Witness-Public-Key-Hash Address and encode with BECH32
- Compare this address with the target address
- If it matches, print the mnemonic and end the program, else continue onto next permutation

Extended functionality
- Optional pasphrase can be added (currently configured to be one of the mnemonic words)

## Setup
```bash
g++ -DNDEBUG -g2 -O2 -I . btcaddresscrack/btcaddresscollider.cxx -o ./btcaddresscollider btcaddresscrack/*.cpp ./cryptopp/libcryptopp.a
./btcaddresscollider
```

## Dependencies
#### [`Cryptopp`](https://www.cryptopp.com/) library
This needs to be pre-compiled after downloading and unzipping. Run `$ make` in the `cryptopp` directory and check that the `libcryptopp.a` file is generated.
