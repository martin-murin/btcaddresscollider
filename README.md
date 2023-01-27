# Cryptographic passphrase encoder for BTC protocol

Run with
```bash
g++ -DNDEBUG -g2 -O2 -I . btcaddresscrack/btcaddresscrack.cxx -o ./test btcaddresscrack/*.cpp ./cryptopp/libcryptopp.a
./test
```

## Dependencies
#### [`Cryptopp`](https://www.cryptopp.com/) library
This needs to be pre-compiled after downloading and unzipping. Run `$ make` in the `cryptopp` directory and check that the `libcryptopp.a` file is generated.
