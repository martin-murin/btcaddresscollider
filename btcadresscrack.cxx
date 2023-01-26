#include "wordlist.h"
#include "segwit_addr.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/osrng.h"
#include "cryptopp/oids.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/hex.h"

#include <iostream>

const char* knownwords[2] = {"hollow", "blast"};
using namespace CryptoPP;

const char* targetHEX = "0x272063C80EBB47CFA3F4CC088187F4B15CE05F7E917BBE7830785B6B16F3CF";
const char* targetB58 = "bc1q7kw2uepv6hfffhhxx2vplkkpcwsslcw9hsupc6";

void byteToStr(const byte inputByteArr[], int size, std::string & outputStr){
    ArraySource strsrc(inputByteArr, size, true,
        new HexEncoder(
            new StringSink(outputStr)
        )
    );
}

void strToByte(const std::string inputStr, byte (& outputByteArr)[], int size){
    StringSource strsrc(inputStr, true,
        new HexDecoder(
            new ArraySink(outputByteArr, size)
        )
    );
}

void check_output_byte(const byte arr[], int size){
    std::string root_str;
    byteToStr(arr, size, root_str);
    std::cout << root_str << std::endl;
}

int main(){

    // test private key from mnemonic
    //std::string someseed = "hollow blast abandon ability able about above absent absorb abstract absurd absurd";
    //byte mnemonic_sentence[] ="carpet rough dish always rich primary service use crisp media purchase apple";
    byte mnemonic_sentence[] = "tip unfair advance patient action teach behind dawn street uphold arrest error";
    size_t mnemlen = strlen((const char*) mnemonic_sentence);

    byte salt[] = "mnemonic";
    size_t slen = strlen((const char*)salt);

    byte derived_seed[SHA512::DIGESTSIZE];
    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    byte unused = 0;
    pbkdf.DeriveKey(derived_seed, sizeof(derived_seed), unused, mnemonic_sentence, mnemlen, salt, slen, 2048, 0.0f);  

    // Output derived seed
    std::string derived_seed_str;
    byteToStr(derived_seed, sizeof(derived_seed), derived_seed_str);
    std::cout << "Derived Seed: " << derived_seed_str << std::endl;
   
    // Generate master extended keys using HMAC SHA512 and Bitcoin seed
    byte root_salt[] = "Bitcoin seed";
    size_t root_slen = strlen((const char*)root_salt);

    byte master_ext_key[SHA512::DIGESTSIZE];
    HMAC< SHA512 > hmac(root_salt, sizeof(root_salt));
    ArraySource arrsrc1(derived_seed, sizeof(derived_seed), true,
        new HashFilter(hmac,
            new ArraySink(master_ext_key, SHA512::DIGESTSIZE)
        )
    );
    
    // Output master extended key
    std::string master_ext_key_str;
    byteToStr(master_ext_key, sizeof(master_ext_key), master_ext_key_str);
    std::cout << "Master Extended Key (Root Key): " << master_ext_key_str << std::endl;


    // Split root key into secret and chain parts
    int secret_size = sizeof(master_ext_key) / 2;
    byte secret_key[secret_size];
    byte chain_key[secret_size];

    memcpy(&secret_key, &master_ext_key, secret_size);
    memcpy(&chain_key, &(master_ext_key[secret_size]), secret_size);
    
    // Output secret key
    std::cout << "Root key:   "; check_output_byte(master_ext_key, 64);
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
    byte pubKeyElementX[32];
    byte pubKeyElementY[32];
    pubKey.GetPublicElement().x.Encode(pubKeyElementX, sizeof(pubKeyElementX));
    pubKey.GetPublicElement().y.Encode(pubKeyElementY, sizeof(pubKeyElementY));

    byte prefix;
    if(pubKey.GetPublicElement().y.IsEven()){
        prefix = 0x02;
    }
    else{
        prefix = 0x03;
    }

    byte compressedPubKey[33];
    memcpy(&compressedPubKey, &prefix, 1);
    memcpy(&(compressedPubKey[1]), &pubKeyElementX, 32);

    // Output compressed public key
    std::string compressedPubKey_str;
    byteToStr(compressedPubKey, sizeof(compressedPubKey), compressedPubKey_str);
    std::cout << "Compressed Public Key: " << compressedPubKey_str << std::endl;

    // Pay-To-Witness-Public-Key-Hash Address (native segwit)
    // ripemd160(sha256(compressedPubKey))
    SHA256 hashSHA256;
    RIPEMD160 hashRIPEMD160;

    byte hashedPubKey[RIPEMD160::DIGESTSIZE];
    ArraySource arrsrc2(compressedPubKey, sizeof(compressedPubKey), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashRIPEMD160,
                new ArraySink(hashedPubKey, RIPEMD160::DIGESTSIZE)
            )
        )
    );

    std::string hashedPubKey_str;
    byteToStr(hashedPubKey, RIPEMD160::DIGESTSIZE, hashedPubKey_str);
    std::cout << "Hashed Public Key: " << hashedPubKey_str << std::endl;

    std::string hrp = "bc";
    int witver = 0;
    std::vector<uint8_t> witprog(&hashedPubKey[0], &hashedPubKey[RIPEMD160::DIGESTSIZE]);
    std::string address_p2wpkh = segwit_addr::encode(hrp, witver, witprog); 
    std::cout << "Address: " << address_p2wpkh << std::endl;
    return 0;
}
