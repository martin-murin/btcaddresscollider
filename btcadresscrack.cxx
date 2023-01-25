#include "wordlist.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

#include <iostream>

const char* knownwords[2] = {"hollow", "blast"};
using namespace CryptoPP;

const char* targetHEX = "0x272063C80EBB47CFA3F4CC088187F4B15CE05F7E917BBE7830785B6B16F3CF";
const char* targetB58 = "bc1q7kw2uepv6hfffhhxx2vplkkpcwsslcw9hsupc6";

void check_output_byte(const byte arr[], int size){
    std::string root_str;
    HexEncoder root_encoder(new StringSink(root_str));
    root_encoder.Put(arr, size);
    root_encoder.MessageEnd();
    std::cout << root_str << std::endl;
}

int main(){

    // test private key from mnemonic
    //std::string someseed = "hollow blast abandon ability able about above absent absorb abstract absurd absurd";
    byte password[] ="carpet rough dish always rich primary service use crisp media purchase apple";
    size_t plen = strlen((const char*)password);

    byte salt[] = "mnemonic";
    size_t slen = strlen((const char*)salt);

    byte derived[SHA512::DIGESTSIZE];
    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    byte unused = 0;
    pbkdf.DeriveKey(derived, sizeof(derived), unused, password, plen, salt, slen, 2048, 0.0f);  

    // Output derived seed
    std::string resultx;
    HexEncoder encoder(new StringSink(resultx));
    encoder.Put(derived, sizeof(derived));
    encoder.MessageEnd();
    std::cout << "Derived: " << resultx << std::endl;
   
    // Second hashing of derived seed to get the root_key
    byte root_salt[] = "Bitcoin seed";
    size_t root_slen = strlen((const char*)root_salt);

    byte root_key[SHA512::DIGESTSIZE];
    pbkdf.DeriveKey(root_key, sizeof(root_key), unused, derived, sizeof(derived), root_salt, root_slen, 2048, 0.0f);

    // Split root key into secret and chain parts
    int secret_size = sizeof(root_key) / 2;
    byte secret_key[secret_size];
    byte chain_key[secret_size];

    for (int i=0; i<secret_size; i++) {
        secret_key[i] = root_key[i];
        chain_key[i]  = root_key[i + secret_size];
    }
    
    // Output secret key
    std::cout << "Root key:   "; check_output_byte(root_key, 64);
    std::cout << "Secret key: "; check_output_byte(secret_key, 32);
    std::cout << "Chain key:  "; check_output_byte(chain_key, 32);

    // Compute private key from root/secret
    std::string secret_str;
    HexEncoder secret_encoder(new StringSink(secret_str));
    secret_encoder.Put(secret_key, sizeof(secret_key));
    secret_encoder.MessageEnd();

    ECDSA<ECP, SHA256>::PrivateKey privKey;
    HexDecoder decoder;
    decoder.Put((byte*) &secret_str[0], secret_str.size());
    decoder.MessageEnd();

    Integer x;    // Private exponent
    x.Decode(decoder, decoder.MaxRetrievable());
    privKey.Initialize(ASN1::secp256k1(), x);

    // Generate public key from private key
    ECDSA<ECP, SHA256>::PublicKey pubKey;
    privKey.MakePublicKey(pubKey);

    pubKey.AccessGroupParameters().SetPointCompression(true);
    std::cout << "Public element x: " << std::hex << pubKey.GetPublicElement().x << std::endl;
    std::cout << "Public element y: " << std::hex << pubKey.GetPublicElement().y << std::endl;

    // Public key compression
    byte compressedPubKey_byte[32];
    pubKey.GetPublicElement().x.Encode(compressedPubKey_byte, 32);
    std::string compressedPubKey_str;
    HexEncoder comppubkey_encoder(new StringSink(compressedPubKey_str));
    comppubkey_encoder.Put(compressedPubKey_byte, sizeof(compressedPubKey_byte));
    secret_encoder.MessageEnd();
    if(pubKey.GetPublicElement().y.IsEven()){
        compressedPubKey_str = "02" + compressedPubKey_str;
    }
    else{
        compressedPubKey_str = "03" + compressedPubKey_str;
    }
    std::cout << "Compressed public key: " << compressedPubKey_str << std::endl;

    // Hash public key to find public address
    //MD5 hash;
    //byte digest[ MD5::DIGESTSIZE ];

    //hash.CalculateDigest( digest, pubKey.GetPublicElement().x, sizeof(pubKey.GetPublicElement().x) );
    return 0;
}
