#include "wordlist.h"
#include "segwit_addr.h"
#include "base58.h"
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

template <unsigned int SIZE> void strToByte(const std::string inputStr, byte (& outputByteArr)[SIZE], int size){
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

void deriveHardChildPrivKey(const byte (& masterPrivKey)[32], const byte (& masterChainCode)[32], unsigned int index, byte (& childPrivKey)[32], byte (& childChainCode)[32]){
    std::cout << "check parent priv key: " << Integer(masterPrivKey, 32) << std::endl;
    byte hashinput[1+sizeof(masterPrivKey)+sizeof(unsigned int)];
    byte hashresult[SHA512::DIGESTSIZE];
    byte index_byte[sizeof(unsigned int)];
    memcpy(index_byte, &index, sizeof(unsigned int));
    std::reverse(index_byte, index_byte+sizeof(unsigned int));
    hashinput[0] = 0x00;
    memcpy(&(hashinput[1]), &masterPrivKey, sizeof(masterPrivKey));
    memcpy(&(hashinput[1+sizeof(masterPrivKey)]), &index_byte, sizeof(unsigned int));
    std::cout << "hash input: "; check_output_byte(hashinput, sizeof(hashinput));
    HMAC< SHA512 > hmacSHA512(masterChainCode, sizeof(masterChainCode));
    ArraySource arrsrc(hashinput, sizeof(hashinput), true,
        new HashFilter(hmacSHA512, 
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );
    std::cout << "hash result: " << Integer(hashresult, 32) << std::endl;
    std::cout << "master priv key: " << Integer(masterPrivKey, 32) << std::endl;
    std::cout << "sum of the two: " << (Integer(hashresult, 32) + Integer(masterPrivKey, 32)) << std::endl;
    std::cout << "Order of the curve: " << Integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h") << "\n";
    Integer childPrivKey_int((Integer(hashresult, 32) + Integer(masterPrivKey, 32)) % Integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h"));
    std::cout << "modulo " << childPrivKey_int << std::endl; 
    childPrivKey_int.Encode(childPrivKey, 32);
    memcpy(&childChainCode, &(hashresult[32]), 32);
}

void deriveSoftChildPrivKey(const byte (& masterPrivKey)[32], const byte (& masterPubKey)[33], const byte (& masterChainCode)[32], unsigned int index, byte (& childPrivKey)[32], byte (& childChainCode)[32]){
    byte hashinput[1+sizeof(masterPubKey)+sizeof(unsigned int)];
    byte hashresult[SHA512::DIGESTSIZE];
    byte index_byte[sizeof(unsigned int)];

    memcpy(index_byte, &index, sizeof(unsigned int));
    std::reverse(index_byte, index_byte+sizeof(unsigned int));

    memcpy(&hashinput, &masterPubKey, sizeof(masterPrivKey));
    memcpy(&(hashinput[sizeof(masterPubKey)]), &index_byte, sizeof(unsigned int));
    
    HMAC< SHA512 > hmacSHA512(masterChainCode, sizeof(masterChainCode));
    ArraySource arrsrc(hashinput, sizeof(hashinput), true,
        new HashFilter(hmacSHA512, 
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );
    Integer childPrivKey_int((Integer(hashresult, 32) + Integer(masterPrivKey, 32)) % Integer("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h"));
    childPrivKey_int.Encode(childPrivKey, 32);
    memcpy(&childChainCode, &(hashresult[32]), 32);
}

void generatePubKeyFromPrivKey(const byte (& privKey)[32], byte (& pubKey)[33]){
    ECDSA<ECP, SHA256>::PrivateKey privateKeyECDSA;
    privateKeyECDSA.Initialize(ASN1::secp256k1(), Integer(privKey, sizeof(privKey)));

    ECDSA<ECP, SHA256>::PublicKey publicKeyECDSA;
    privateKeyECDSA.MakePublicKey(publicKeyECDSA);
    publicKeyECDSA.AccessGroupParameters().SetPointCompression(true);

    // Public key compression
    byte pubKeyElementX[32];
    byte pubKeyElementY[32];
    publicKeyECDSA.GetPublicElement().x.Encode(pubKeyElementX, sizeof(pubKeyElementX));
    publicKeyECDSA.GetPublicElement().y.Encode(pubKeyElementY, sizeof(pubKeyElementY));

    if(publicKeyECDSA.GetPublicElement().y.IsEven()){
        pubKey[0] = 0x02;
    }
    else{
        pubKey[0] = 0x03;
    }
    memcpy(&(pubKey[1]), &pubKeyElementX, 32);
}

void hash160(const byte (& publicKey)[33], byte (& hashedPubKey)[RIPEMD160::DIGESTSIZE]){
    // ripemd160(sha256(publicKey))
    SHA256 hashSHA256;
    RIPEMD160 hashRIPEMD160;

    ArraySource arrsrc(publicKey, sizeof(publicKey), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashRIPEMD160,
                new ArraySink(hashedPubKey, RIPEMD160::DIGESTSIZE)
            )
        )
    );
}

void serializationPrefix(char* version, byte depth, const byte (& parentPublicKey)[33], unsigned int childNumber, byte (& serialPrefix)[13]){
    // Version bytes of the key ("zprv" and "zpub" in BIP 84 derivation path)
    byte ver[4];
    if(version == "zprv"){ver[0] = 0x04; ver[1] = 0xb2; ver[2] = 0x43; ver[3] = 0x0c;}
    else if(version == "zpub"){ver[0] = 0x04; ver[1] = 0xb2; ver[2] = 0x47; ver[3] = 0x46;}
    else if(version == "yprv"){ver[0] = 0x04; ver[1] = 0x9d; ver[2] = 0x78; ver[3] = 0x78;}
    else if(version == "ypub"){ver[0] = 0x04; ver[1] = 0x9d; ver[2] = 0x7c; ver[3] = 0xb2;}
    else if(version == "xprv"){ver[0] = 0x04; ver[1] = 0x88; ver[2] = 0xad; ver[3] = 0xe4;}
    else if(version == "xpub"){ver[0] = 0x04; ver[1] = 0x88; ver[2] = 0xb2; ver[3] = 0x1e;}
    else{ver[0] = 0x00; ver[1] = 0x00; ver[2] = 0x00; ver[3] = 0x00;}
    
    // Convert child number into byte array
    byte childN[sizeof(unsigned int)];
    memcpy(childN, &childNumber, sizeof(unsigned int));
    std::reverse(childN, childN+sizeof(unsigned int));

    // Parent fingerprint is HASH160 of the public key
    byte parentFingerprint[RIPEMD160::DIGESTSIZE];
    hash160(parentPublicKey, parentFingerprint);

    // Write serialization prefix
    memcpy(&serialPrefix, &ver, 4);
    serialPrefix[4] = depth;
    memcpy(&(serialPrefix[5]), parentFingerprint, 4);
    memcpy(&(serialPrefix[9]), childN, sizeof(unsigned int));
}

template <unsigned int KEYSIZE> void serializeKey(const byte (& prefix)[13], const byte (& key)[KEYSIZE], const byte (& chain)[32], byte (& serializedKey)[82], std::string & serializedKey_str){
    // Prepare byte sequence for SHA256 hash
    byte tempSequence[78];
    memcpy(&tempSequence, &prefix, sizeof(prefix));
    memcpy(&(tempSequence[sizeof(prefix)]), &chain, sizeof(chain));
    tempSequence[sizeof(prefix)+sizeof(chain)] = 0x00;
    memcpy(&(tempSequence[sizeof(tempSequence)-sizeof(key)]), key, sizeof(key));

    // Obtain checksum using SHA256
    SHA256 hashSHA256;
    byte checksum[SHA256::DIGESTSIZE];
    ArraySource arrsrc(tempSequence, sizeof(tempSequence), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashSHA256,
                new ArraySink(checksum, SHA256::DIGESTSIZE)
            )
        )
    );

    // Write serialized key and checksum 
    memcpy(&serializedKey, &tempSequence, 78);
    memcpy(&(serializedKey[78]), &checksum, 4);
    
    // Convert to base58
    std::vector<uint8_t> serializedKey_uint8(&serializedKey[0], &serializedKey[sizeof(serializedKey)]);
    serializedKey_str = EncodeBase58(serializedKey_uint8, base58map);
}

std::string getAddressP2WPKH(const byte (& publicKey)[33]){
    // Pay-To-Witness-Public-Key-Hash Address (native segwit)
    byte hashedPubKey[RIPEMD160::DIGESTSIZE];
    hash160(publicKey, hashedPubKey);

    // Encode with BECH32
    std::string hrp = "bc";         // human readable part
    int witver = 0;                 // witness version
    std::vector<uint8_t> witprog(&hashedPubKey[0], &hashedPubKey[RIPEMD160::DIGESTSIZE]);
    std::string address_p2wpkh = segwit_addr::encode(hrp, witver, witprog);
    return address_p2wpkh;

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

    byte masterPrivKey[SHA512::DIGESTSIZE];
    HMAC< SHA512 > hmac(root_salt, sizeof(root_salt));
    ArraySource arrsrc1(derived_seed, sizeof(derived_seed), true,
        new HashFilter(hmac,
            new ArraySink(masterPrivKey, SHA512::DIGESTSIZE)
        )
    );
    
    // Output master extended key
    std::string masterPrivKey_str;
    byteToStr(masterPrivKey, sizeof(masterPrivKey), masterPrivKey_str);
    std::cout << "Master Extended Key (Root Key): " << masterPrivKey_str << std::endl;

    // Split root key into secret and chain parts
    int secret_size = sizeof(masterPrivKey) / 2;
    byte secret_key[32];
    byte chain_key[32];

    memcpy(&secret_key, &masterPrivKey, secret_size);
    memcpy(&chain_key, &(masterPrivKey[secret_size]), secret_size);

    // Output secret key
    std::cout << "Root key:   "; check_output_byte(masterPrivKey, 64);
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

    Integer x(secret_key, 32);    // Private exponent
    //x.Decode(decoder, decoder.MaxRetrievable());
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

    byte compressedPubKey[33];
    if(pubKey.GetPublicElement().y.IsEven()){
        compressedPubKey[0] = 0x02;
    }
    else{
        compressedPubKey[0] = 0x03;
    }
    memcpy(&(compressedPubKey[1]), &pubKeyElementX, 32);

    // Output compressed public key
    std::string compressedPubKey_str;
    byteToStr(compressedPubKey, sizeof(compressedPubKey), compressedPubKey_str);
    std::cout << "Compressed Public Key: " << compressedPubKey_str << std::endl;


    // Serialized master keys
    //byte versionPrefixPriv[] {0x0488ADE4};  //xprv in BIP32 
    //byte versionPrefixPub[] {0x0488B21E};   //xpub in BIP32
    byte depth[] {0x00};                    //0x00 for master, 0x01 for level-1 derived...
    byte zero[] {0x00};
    byte fingerprint[] {0x00000000};
    byte childnumber[] {0x00000000};
    byte fullPrefixPriv[] {0x04, 0xb2, 0x43, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte fullPrefixPub[] {0x04, 0xb2, 0x47, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte serializedMasterPrivKey[78];
    memcpy(&serializedMasterPrivKey, &fullPrefixPriv, sizeof(fullPrefixPriv));
    memcpy(&(serializedMasterPrivKey[sizeof(fullPrefixPriv)]), &chain_key, sizeof(chain_key));
    memcpy(&(serializedMasterPrivKey[sizeof(fullPrefixPriv)+sizeof(chain_key)]), &zero, 1);
    memcpy(&(serializedMasterPrivKey[sizeof(fullPrefixPriv)+sizeof(chain_key)+1]), secret_key, sizeof(secret_key));

    SHA256 hashSHA256;
    byte checksum[SHA256::DIGESTSIZE];
    ArraySource arrsrc3(serializedMasterPrivKey, sizeof(serializedMasterPrivKey), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashSHA256,
                new ArraySink(checksum, SHA256::DIGESTSIZE)
            )
        )
    );
    byte serializedMasterPrivKeyCheck[82];
    memcpy(&serializedMasterPrivKeyCheck, &serializedMasterPrivKey, 78);
    memcpy(&(serializedMasterPrivKeyCheck[78]), &checksum, 4);
    std::string serializedMasterPrivKeyCheck_str;
    byteToStr(serializedMasterPrivKeyCheck, sizeof(serializedMasterPrivKeyCheck), serializedMasterPrivKeyCheck_str);
    std::cout << "Serialized Master Private Key: " << serializedMasterPrivKeyCheck_str << std::endl;
    
    std::vector<uint8_t> serializedMasterPrivKeyCheck_uint8(&serializedMasterPrivKeyCheck[0], &serializedMasterPrivKeyCheck[sizeof(serializedMasterPrivKeyCheck)]);
    std::string serializedMasterPrivKeyCheck_str_b58 = EncodeBase58(serializedMasterPrivKeyCheck_uint8, base58map);
    std::cout << "Serialized Master Private Key (base58): " << serializedMasterPrivKeyCheck_str_b58 << std::endl;

    // Serialise public key
    byte serializedMasterPubKey[78];
    memcpy(&serializedMasterPubKey, &fullPrefixPub, sizeof(fullPrefixPub));
    memcpy(&(serializedMasterPubKey[sizeof(fullPrefixPub)]), &chain_key, sizeof(chain_key));
    memcpy(&(serializedMasterPubKey[sizeof(fullPrefixPub) + sizeof(chain_key)]), compressedPubKey, sizeof(compressedPubKey));

    ArraySource arrsrc4(serializedMasterPubKey, sizeof(serializedMasterPubKey), true,
        new HashFilter(hashSHA256,
            new HashFilter(hashSHA256,
                new ArraySink(checksum, SHA256::DIGESTSIZE)
            )
        )
    );
    byte serializedMasterPubKeyCheck[82];
    memcpy(&serializedMasterPubKeyCheck, &serializedMasterPubKey, 78);
    memcpy(&(serializedMasterPubKeyCheck[78]), &checksum, 4);
    std::string serializedMasterPubKeyCheck_str;
    byteToStr(serializedMasterPubKeyCheck, sizeof(serializedMasterPubKeyCheck), serializedMasterPubKeyCheck_str);
    std::cout << "Serialized Master Public Key: " << serializedMasterPubKeyCheck_str << std::endl;

    std::vector<uint8_t> serializedMasterPubKeyCheck_uint8(&serializedMasterPubKeyCheck[0], &serializedMasterPubKeyCheck[sizeof(serializedMasterPubKeyCheck)]);
    std::string serializedMasterPubKeyCheck_str_b58 = EncodeBase58(serializedMasterPubKeyCheck_uint8, base58map);
    std::cout << "Serialized Master Pubate Key (base58): " << serializedMasterPubKeyCheck_str_b58 << std::endl;

    // Pay-To-Witness-Public-Key-Hash Address (native segwit)
    // ripemd160(sha256(compressedPubKey))
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

    // Test derive hard child key
    std::string parent_chain_code  = "463223aac10fb13f291a1bc76bc26003d98da661cb76df61e750c139826dea8b";
    std::string parent_private_key = "f79bb0d317b310b261a55a8ab393b4c8a1aba6fa4d08aef379caba502d5d67f9";
    byte parent_chain_code_byte[32];
    byte parent_private_key_byte[32];
    strToByte(parent_chain_code, parent_chain_code_byte, 32);
    strToByte(parent_private_key, parent_private_key_byte, 32);
    unsigned int index = 2147483648;
    byte hard_child_priv_key[32];
    byte hard_child_chain_code[32];
    deriveHardChildPrivKey(parent_private_key_byte, parent_chain_code_byte, index, hard_child_priv_key, hard_child_chain_code);
    std::cout << "hardened child priv key: "; check_output_byte(hard_child_priv_key, 32);
    std::cout << "hardened child chain code: "; check_output_byte(hard_child_chain_code, 32);

    // BIP 84 derivation path m/84'/0'/0'/0/0
    byte child_84_privKey[32];
    byte child_84_pubKey[33];
    byte child_84_chainCode[32];
    byte child_84_privPrefix[13];
    byte child_84_pubPrefix[13];
    byte child_84_0h_privKey[32];
    byte child_84_0h_pubKey[33];
    byte child_84_0h_chainCode[32];
    byte child_84_0h_privPrefix[13];
    byte child_84_0h_pubPrefix[13];
    byte child_84_0h_0h_privKey[32];
    byte child_84_0h_0h_pubKey[33];
    byte child_84_0h_0h_chainCode[32];
    byte child_84_0h_0h_privPrefix[13];
    byte child_84_0h_0h_pubPrefix[13];
    byte child_84_0h_0h_0_privKey[32];
    byte child_84_0h_0h_0_pubKey[33];
    byte child_84_0h_0h_0_chainCode[32];
    byte child_84_0h_0h_0_privPrefix[13];
    byte child_84_0h_0h_0_pubPrefix[13];
    byte child_84_0h_0h_0_0_privKey[32];
    byte child_84_0h_0h_0_0_pubKey[33];
    byte child_84_0h_0h_0_0_chainCode[32];
    byte child_84_0h_0h_0_0_privPrefix[13];
    byte child_84_0h_0h_0_0_pubPrefix[13];
    
    unsigned int index_hard = 2147483648;
    
    //void serializationPrefix(char* version, byte depth, const byte (& parentPublicKey)[33], unsigned int childNumber, byte (& serialPrefix)[13]){
    deriveHardChildPrivKey(secret_key, chain_key, index_hard+84, child_84_privKey, child_84_chainCode);
    generatePubKeyFromPrivKey(child_84_privKey, child_84_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x01, compressedPubKey, index_hard+84, child_84_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x01, compressedPubKey, index_hard+84, child_84_pubPrefix);
    
    deriveHardChildPrivKey(child_84_privKey, child_84_chainCode, index_hard, child_84_0h_privKey, child_84_0h_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_privKey, child_84_0h_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x02, child_84_pubKey, index_hard, child_84_0h_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x02, child_84_pubKey, index_hard, child_84_0h_pubPrefix);
    
    deriveHardChildPrivKey(child_84_0h_privKey, child_84_0h_chainCode, index_hard, child_84_0h_0h_privKey, child_84_0h_0h_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_0h_privKey, child_84_0h_0h_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x03, child_84_0h_pubKey, index_hard, child_84_0h_0h_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x03, child_84_0h_pubKey, index_hard, child_84_0h_0h_pubPrefix);

    deriveSoftChildPrivKey(child_84_0h_0h_privKey, child_84_0h_0h_pubKey, child_84_0h_0h_chainCode, 0, child_84_0h_0h_0_privKey, child_84_0h_0h_0_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_0h_0_privKey, child_84_0h_0h_0_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x04, child_84_0h_0h_pubKey, 0, child_84_0h_0h_0_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x04, child_84_0h_0h_pubKey, 0, child_84_0h_0h_0_pubPrefix);

    deriveSoftChildPrivKey(child_84_0h_0h_0_privKey, child_84_0h_0h_0_pubKey, child_84_0h_0h_0_chainCode, 0, child_84_0h_0h_0_0_privKey, child_84_0h_0h_0_0_chainCode);
    generatePubKeyFromPrivKey(child_84_0h_0h_0_0_privKey, child_84_0h_0h_0_0_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x05, child_84_0h_0h_0_pubKey, 0, child_84_0h_0h_0_0_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x05, child_84_0h_0h_0_pubKey, 0, child_84_0h_0h_0_0_pubPrefix);

    //template <unsigned int KEYSIZE> void serializeKey(const byte (& prefix)[13], const byte (& key)[KEYSIZE], const byte (& chain)[32], byte (& serializedKey)[82], std::string & serializedKey_str)
    //std::string getAddressP2WPKH(const byte (& publicKey)[33]){
    byte child_84_privKey_serialized[82];
    byte child_84_pubKey_serialized[82];
    std::string child_84_privKey_serialized_str;
    std::string child_84_pubKey_serialized_str;
    serializeKey(child_84_privPrefix, child_84_privKey, child_84_chainCode, child_84_privKey_serialized, child_84_privKey_serialized_str);
    serializeKey(child_84_pubPrefix, child_84_pubKey, child_84_chainCode, child_84_pubKey_serialized, child_84_pubKey_serialized_str);
    std::string child_84_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_pubKey);

    byte child_84_0h_0h_0_privKey_serialized[82];
    byte child_84_0h_0h_0_pubKey_serialized[82];
    std::string child_84_0h_0h_0_privKey_serialized_str;
    std::string child_84_0h_0h_0_pubKey_serialized_str;
    serializeKey(child_84_0h_0h_0_privPrefix, child_84_0h_0h_0_privKey, child_84_0h_0h_0_chainCode, child_84_0h_0h_0_privKey_serialized, child_84_0h_0h_0_privKey_serialized_str);
    serializeKey(child_84_0h_0h_0_pubPrefix, child_84_0h_0h_0_pubKey, child_84_0h_0h_0_chainCode, child_84_0h_0h_0_pubKey_serialized, child_84_0h_0h_0_pubKey_serialized_str);
    std::string child_84_0h_0h_0_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_0h_0_pubKey);
    
    byte child_84_0h_0h_0_0_privKey_serialized[82];
    byte child_84_0h_0h_0_0_pubKey_serialized[82];
    std::string child_84_0h_0h_0_0_privKey_serialized_str;
    std::string child_84_0h_0h_0_0_pubKey_serialized_str;
    serializeKey(child_84_0h_0h_0_0_privPrefix, child_84_0h_0h_0_0_privKey, child_84_0h_0h_0_0_chainCode, child_84_0h_0h_0_0_privKey_serialized, child_84_0h_0h_0_0_privKey_serialized_str);
    serializeKey(child_84_0h_0h_0_0_pubPrefix, child_84_0h_0h_0_0_pubKey, child_84_0h_0h_0_0_chainCode, child_84_0h_0h_0_0_pubKey_serialized, child_84_0h_0h_0_0_pubKey_serialized_str);
    std::string child_84_0h_0h_0_0_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_0h_0_0_pubKey);

    std::cout << "\n======= DERIVATION TREE FOR BIP 84 ========\n";
    std::cout << "child_84_privKey_serialized:             " << child_84_privKey_serialized_str << std::endl;
    std::cout << "child_84_pubKey_serialized:              " << child_84_pubKey_serialized_str << std::endl;
    std::cout << "child_84_pubKey_addressP2WPKH:           " << child_84_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_0_privKey_serialized:     " << child_84_0h_0h_0_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_pubKey_serialized:      " << child_84_0h_0h_0_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_pubKey_addressP2WPKH    " << child_84_0h_0h_0_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_0_0_privKey_serialized:   " << child_84_0h_0h_0_0_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_0_pubKey_serialized:    " << child_84_0h_0h_0_0_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_0_pubKey_addressP2WPKH  " << child_84_0h_0h_0_0_pubKey_addressP2WPKH << std::endl;

    return 0;
}
