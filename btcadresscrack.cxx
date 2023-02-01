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

using namespace CryptoPP;

// Global variables
#define MAX_WORDS 2048
const Integer SECP256K1_CURVE_ORDER("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141h");
//const char* TARGET_ADDRESS = "bc1q7kw2uepv6hfffhhxx2vplkkpcwsslcw9hsupc6";
const char* TARGET_ADDRESS = "bc1qtkh4mq24ev94j9usmlkxq0plfax9z8ztreadcx";
const int N_WORDS = 13;
//const char* KNOWN_WORDS[13] = {"hollow", "blast", "monkey", "love", "strike", "lion", "target", "river", "valley", "town", "pistol", "", ""};
const char* KNOWN_WORDS[13] = {"skull", "faint", "enter", "welcome", "later", "drift", "depart", "moral", "other", "wealth", "logic", "bacon", "blast"};

int checkAddressCollisionWithTarget(const char* sentence, const char* passphrase);

// Conversion from byte array to string
//template <unsigned int SIZE> std::string byteToStr(const byte (& inputByteArr)[SIZE]){
std::string byteToStr(const byte* inputByteArr, int SIZE){
    std::string outputStr;
    ArraySource strsrc(inputByteArr, SIZE, true,
        new HexEncoder(
            new StringSink(outputStr)
        )
    );
    return outputStr;
}

// Conversion from string to byte array
template <unsigned int SIZE> void strToByte(const std::string inputStr, byte (& outputByteArr)[SIZE], int size){
    StringSource strsrc(inputStr, true,
        new HexDecoder(
            new ArraySink(outputByteArr, size)
        )
    );
}

// Derivation of Seed from Mnemonic phrase and Salt using Password Based Key Derivation Function
//template <unsigned int MNEMSIZE, unsigned int SALTSIZE> void deriveSeedFromMnemonic(const byte (& mnemonicSentence)[MNEMSIZE], const byte (& salt)[SALTSIZE], byte (& derivedSeed)[SHA512::DIGESTSIZE]){
void deriveSeedFromMnemonic(const byte* mnemonicSentence, int mnem__size, const byte* salt, int salt__size, byte (& derivedSeed)[SHA512::DIGESTSIZE]){
    // Password Based Key Derivation Function
    PKCS5_PBKDF2_HMAC<SHA512> hashPBKDF2;
    size_t mnem_size = strlen((const char*) mnemonicSentence);
    size_t salt_size = strlen((const char*) salt);
    size_t seed_size = sizeof(derivedSeed);
    hashPBKDF2.DeriveKey(derivedSeed, seed_size, 0x00, mnemonicSentence, mnem_size, salt, salt_size, 2048, 0.0f);
}

// Derivation of the Master Key and Chain Code from the Seed
void deriveMasterKeyFromSeed(const byte (& seed)[SHA512::DIGESTSIZE], byte (& masterPrivKey)[32], byte (& masterChainCode)[32]){
    byte salt[] = "Bitcoin seed";
    unsigned int salt_size = sizeof(salt);

    byte hashresult[SHA512::DIGESTSIZE];
    HMAC< SHA512 > hmacSHA512(salt, salt_size);
    ArraySource arrsrc(seed, sizeof(seed), true,
        new HashFilter(hmacSHA512,
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );

    // Split hash result into private key (left 32 bytes) and chain code (right 32 bytes)
    memcpy(&masterPrivKey, &hashresult, 32);
    memcpy(&masterChainCode, &(hashresult[32]), 32);
}

// Generate Public Key from Private Key using Elliptic Curve Digital Signature Algorithm with secp256k1 curve
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

// Derive hardened children private keys
void deriveHardChildPrivKey(const byte (& masterPrivKey)[32], const byte (& masterChainCode)[32], unsigned int index, byte (& childPrivKey)[32], byte (& childChainCode)[32]){
    byte hashinput[1+sizeof(masterPrivKey)+sizeof(unsigned int)];
    byte hashresult[SHA512::DIGESTSIZE];
    byte index_byte[sizeof(unsigned int)];
    
    memcpy(index_byte, &index, sizeof(unsigned int));
    // Convert from little endian to big endian
    std::reverse(index_byte, index_byte+sizeof(unsigned int));

    hashinput[0] = 0x00;
    memcpy(&(hashinput[1]), &masterPrivKey, sizeof(masterPrivKey));
    memcpy(&(hashinput[1+sizeof(masterPrivKey)]), &index_byte, sizeof(unsigned int));
    
    HMAC< SHA512 > hmacSHA512(masterChainCode, sizeof(masterChainCode));
    ArraySource arrsrc(hashinput, sizeof(hashinput), true,
        new HashFilter(hmacSHA512, 
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );

    // Scalar addition of hash result with Private Key modulo order of the curve
    Integer childPrivKey_int((Integer(hashresult, 32) + Integer(masterPrivKey, 32)) % SECP256K1_CURVE_ORDER);
    childPrivKey_int.Encode(childPrivKey, 32);
    memcpy(&childChainCode, &(hashresult[32]), 32);
}

// Derive normal children private keys
void deriveSoftChildPrivKey(const byte (& masterPrivKey)[32], const byte (& masterPubKey)[33], const byte (& masterChainCode)[32], unsigned int index, byte (& childPrivKey)[32], byte (& childChainCode)[32]){
    byte hashinput[sizeof(masterPubKey)+sizeof(unsigned int)];
    byte hashresult[SHA512::DIGESTSIZE];
    byte index_byte[sizeof(unsigned int)];

    memcpy(index_byte, &index, sizeof(unsigned int));
    // Convert from little endian to big endian
    std::reverse(index_byte, index_byte+sizeof(unsigned int));

    memcpy(&hashinput, &masterPubKey, sizeof(masterPubKey));
    memcpy(&(hashinput[sizeof(masterPubKey)]), &index_byte, sizeof(unsigned int));
    
    HMAC< SHA512 > hmacSHA512(masterChainCode, sizeof(masterChainCode));
    ArraySource arrsrc(hashinput, sizeof(hashinput), true,
        new HashFilter(hmacSHA512, 
            new ArraySink(hashresult, SHA512::DIGESTSIZE)
        )
    );

    // Scalar addition of hash result with Private Key modulo order of the curve
    Integer childPrivKey_int((Integer(hashresult, 32) + Integer(masterPrivKey, 32)) % SECP256K1_CURVE_ORDER);
    childPrivKey_int.Encode(childPrivKey, 32);
    memcpy(&childChainCode, &(hashresult[32]), 32);
}

// HASH160 is RIPEMD160 after SHA256 used for public addresses and parent fingerprint in serialization
void hash160(const byte (& publicKey)[33], byte (& hashedPubKey)[RIPEMD160::DIGESTSIZE]){
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

// Calculate serialization prefix based on version number, depth of the child in key tree hierarchy, parent public key and the number of the child 
void serializationPrefix(char* version, byte depth, const byte (& parentPublicKey)[33], unsigned int childNumber, byte (& serialPrefix)[13]){
    // Version bytes of the key ("zprv" and "zpub" in BIP 84 derivation path)
    byte ver[4];
    if(strcmp(version, "zprv") == 0){ver[0] = 0x04; ver[1] = 0xb2; ver[2] = 0x43; ver[3] = 0x0c;}
    else if(strcmp(version, "zpub") == 0){ver[0] = 0x04; ver[1] = 0xb2; ver[2] = 0x47; ver[3] = 0x46;}
    else if(strcmp(version, "yprv") == 0){ver[0] = 0x04; ver[1] = 0x9d; ver[2] = 0x78; ver[3] = 0x78;}
    else if(strcmp(version, "ypub") == 0){ver[0] = 0x04; ver[1] = 0x9d; ver[2] = 0x7c; ver[3] = 0xb2;}
    else if(strcmp(version, "xprv") == 0){ver[0] = 0x04; ver[1] = 0x88; ver[2] = 0xad; ver[3] = 0xe4;}
    else if(strcmp(version, "xpub") == 0){ver[0] = 0x04; ver[1] = 0x88; ver[2] = 0xb2; ver[3] = 0x1e;}
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

// Generate serialized key as byte array and string, from the prefix, key, and chain code
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

// Calculate Pay-To-Witness-Public-Key-Hash Address (native segwit)
std::string getAddressP2WPKH(const byte (& publicKey)[33]){
    byte hashedPubKey[RIPEMD160::DIGESTSIZE];
    hash160(publicKey, hashedPubKey);

    // Encode with BECH32
    std::string hrp = "bc";         // human readable part
    int witver = 0;                 // witness version
    std::vector<uint8_t> witprog(&hashedPubKey[0], &hashedPubKey[RIPEMD160::DIGESTSIZE]);
    std::string address_p2wpkh = segwit_addr::encode(hrp, witver, witprog);
    return address_p2wpkh;

}

// Find index of a given word in the word list using binary search
int findIndexInWordlist(const char* word, int start, int end) {
    if (start <= end) {
        int mid = start + (end - start) / 2;
        int result = strcmp(word, BTC_WORD_LIST[mid]);
        if (result == 0) {
            return mid;
        } else if (result < 0) {
            return findIndexInWordlist(word, start, mid - 1);
        } else {
            return findIndexInWordlist(word, mid + 1, end);
        }
    }
    return -1;
}

bool verifyMnemonicChecksum(const char** words){
    // TODO:
    // split into mnemonic sentence and passphrase
    // find index for each of mnemonic sentence words
    // convert and split into 128 bit input and 4 bit checksum
    // calculate checksum of 128 bit input using SHA256
    // get the first 4 bits from checksum and compare with last 4 bits of mnemonic sentence
    int indWords[12];
    for (int i = 0; i < 12; i++){
        indWords[i] = findIndexInWordlist(words[i], 0, MAX_WORDS);
    }
    
    byte first4;
    int last4 = indWords[11] & 0x0F;
    return false;
}

char* concatenateListIntoSentence(const char** wordlist, int n) {
    int length = 0;
    for (int i = 0; i < n; i++) {
        length += strlen(wordlist[i]) + 1;  // +1 for space
    }
    char* sentence = static_cast<char*>(malloc(length));
    sentence[0] = '\0';
    for (int i = 0; i < n; i++) {
        strcat(sentence, wordlist[i]);
        if (i < n - 1) {
            strcat(sentence, " ");
        }
    }
    return sentence;
}

// Recursive function which generates all permutations of the list of words
void loopPermutations(const char** arr, int l, int r) {
    if (l == r) {
        // Verify validity of this permutation as the mnemonic sentence
        // if (verifyMnemonicChecksum(arr) { ...  }
        const char* sentence = concatenateListIntoSentence(arr, N_WORDS-1);
        const char* passphrase = arr[N_WORDS-1]; 
        // Check address collision with target
        int status = checkAddressCollisionWithTarget(sentence, passphrase);
        if (status == 1){
            std::cout << std::endl << "******** COLLISION ********" << std::endl;
            exit(0);
        }
    } else {
        for (int i = l; i <= r; i++) {
            // Swap elements at index l and i
            std::swap(arr[l], arr[i]);
            // Recursively permute the subarray arr[l+1...r]
            loopPermutations(arr, l+1, r);
            // Swap back the elements to restore the original array
            std::swap(arr[l], arr[i]);
        }
    }
}

// Recursive function which generates all combinations of the remaining missing words
void loopCombinations(const char* words[], int currIndex, int numWords){
    if (currIndex == numWords) {
        // Launch permutations of this combination
        loopPermutations(words, 0, numWords-1);
        return;
    }
    // Check if the current word is filled in
    if (strlen(words[currIndex]) > 0) {
        // If yes, go to the next word
        loopCombinations(words, currIndex + 1, numWords);
    } else {
        // Else, loop over all possible words and go to the next word each time
        for (int i = 0; i < MAX_WORDS; i++) {
            words[currIndex] = BTC_WORD_LIST[i];
            loopCombinations(words, currIndex + 1, numWords);
            words[currIndex] = "";
        }
    }
}

int checkAddressCollisionWithTarget(const char* sentence, const char* passphrase){
    // Prepare mnemonic sentence into byte array
    int lengthOfMnemSentence = strlen(sentence);
    byte mnemonicSentence[lengthOfMnemSentence+1];
    for (int i = 0; i < lengthOfMnemSentence; i++){
        mnemonicSentence[i] = static_cast<unsigned char>(sentence[i]);
    }
    mnemonicSentence[lengthOfMnemSentence] = 0x00;

    // Prepare passphrase into byte array
    byte mnemBase[] = "mnemonic";
    int lengthOfPassphrase = strlen(passphrase);
    byte mnemPassphrase[lengthOfPassphrase+1];
    for (int i = 0; i < lengthOfPassphrase; i++){
        mnemPassphrase[i] = static_cast<unsigned char>(passphrase[i]);
    }
    mnemPassphrase[lengthOfPassphrase] = 0x00;

    byte mnemonicSalt[sizeof(mnemBase)+sizeof(mnemPassphrase)-1];
    memcpy(&mnemonicSalt, &mnemBase, sizeof(mnemBase));
    memcpy(&(mnemonicSalt[sizeof(mnemBase)-1]), &mnemPassphrase, sizeof(mnemPassphrase));

    // Generate seed, private/public key pair, chain code and prefixes
    byte master_seed[SHA512::DIGESTSIZE];
    byte master_privKey[32];
    byte master_pubKey[33];
    byte master_chainCode[32];
    byte master_privPrefix[13];
    byte master_pubPrefix[13];

    deriveSeedFromMnemonic(mnemonicSentence, sizeof(mnemonicSentence), mnemonicSalt, sizeof(mnemonicSalt), master_seed);
    deriveMasterKeyFromSeed(master_seed, master_privKey, master_chainCode);
    generatePubKeyFromPrivKey(master_privKey, master_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x00, master_pubKey, 0, master_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x00, master_pubKey, 0, master_pubPrefix);

    // Print
    std::cout << "============== MASTER KEY =============" << std::endl;
    std::cout << "Mnemonic sentence (human readable):    " << reinterpret_cast<const char*>(mnemonicSentence) << std::endl;
    std::cout << "Mnemonic SALT (human readable):        " << reinterpret_cast<const char*>(mnemonicSalt) << std::endl;
    std::cout << "Mnemonic sentence:                     " << byteToStr(mnemonicSentence, sizeof(mnemonicSentence)) << std::endl;
    std::cout << "Mnemonic base:                         " << byteToStr(mnemBase, sizeof(mnemBase)) << std::endl;
    std::cout << "Passphrase:                            " << byteToStr(mnemPassphrase, lengthOfPassphrase) << std::endl;
    std::cout << "Mnemonic SALT:                         " << byteToStr(mnemonicSalt, sizeof(mnemonicSalt)) << std::endl;
    std::cout << "SEED:                                  " << byteToStr(master_seed, sizeof(master_seed)) << std::endl;
    std::cout << "MASTER PRIVATE KEY:                    " << byteToStr(master_privKey, sizeof(master_privKey)) << std::endl;
    std::cout << "MASTER PUBLIC KEY:                     " << byteToStr(master_pubKey, sizeof(master_pubKey)) << std::endl;
    std::cout << "Master chain code:                     " << byteToStr(master_chainCode, sizeof(master_chainCode)) << std::endl;
    std::cout << std::endl;


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
    
    // Index for hardened child (can not be derived from public key)
    unsigned int index_hard = 2147483648;
    
    // Derive hierarchy of keys in the derivation path
    deriveHardChildPrivKey(master_privKey, master_chainCode, index_hard+84, child_84_privKey, child_84_chainCode);
    generatePubKeyFromPrivKey(child_84_privKey, child_84_pubKey);
    serializationPrefix(const_cast<char*>("zprv"), 0x01, master_pubKey, index_hard+84, child_84_privPrefix);
    serializationPrefix(const_cast<char*>("zpub"), 0x01, master_pubKey, index_hard+84, child_84_pubPrefix);
    
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

    // Serialization
    byte master_privKey_serialized[82];
    byte master_pubKey_serialized[82];
    std::string master_privKey_serialized_str;
    std::string master_pubKey_serialized_str;
    serializeKey(master_privPrefix, master_privKey, master_chainCode, master_privKey_serialized, master_privKey_serialized_str);
    serializeKey(master_pubPrefix, master_pubKey, master_chainCode, master_pubKey_serialized, master_pubKey_serialized_str);
    std::string master_pubKey_addressP2WPKH = getAddressP2WPKH(master_pubKey);

    byte child_84_privKey_serialized[82];
    byte child_84_pubKey_serialized[82];
    std::string child_84_privKey_serialized_str;
    std::string child_84_pubKey_serialized_str;
    serializeKey(child_84_privPrefix, child_84_privKey, child_84_chainCode, child_84_privKey_serialized, child_84_privKey_serialized_str);
    serializeKey(child_84_pubPrefix, child_84_pubKey, child_84_chainCode, child_84_pubKey_serialized, child_84_pubKey_serialized_str);
    std::string child_84_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_pubKey);

    byte child_84_0h_privKey_serialized[82];
    byte child_84_0h_pubKey_serialized[82];
    std::string child_84_0h_privKey_serialized_str;
    std::string child_84_0h_pubKey_serialized_str;
    serializeKey(child_84_0h_privPrefix, child_84_0h_privKey, child_84_0h_chainCode, child_84_0h_privKey_serialized, child_84_0h_privKey_serialized_str);
    serializeKey(child_84_0h_pubPrefix, child_84_0h_pubKey, child_84_0h_chainCode, child_84_0h_pubKey_serialized, child_84_0h_pubKey_serialized_str);
    std::string child_84_0h_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_pubKey);

    byte child_84_0h_0h_privKey_serialized[82];
    byte child_84_0h_0h_pubKey_serialized[82];
    std::string child_84_0h_0h_privKey_serialized_str;
    std::string child_84_0h_0h_pubKey_serialized_str;
    serializeKey(child_84_0h_0h_privPrefix, child_84_0h_0h_privKey, child_84_0h_0h_chainCode, child_84_0h_0h_privKey_serialized, child_84_0h_0h_privKey_serialized_str);
    serializeKey(child_84_0h_0h_pubPrefix, child_84_0h_0h_pubKey, child_84_0h_0h_chainCode, child_84_0h_0h_pubKey_serialized, child_84_0h_0h_pubKey_serialized_str);
    std::string child_84_0h_0h_pubKey_addressP2WPKH = getAddressP2WPKH(child_84_0h_0h_pubKey);

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

    // Print
    std::cout << "\n======= DERIVATION TREE FOR BIP 84 ========\n";
    std::cout << "master_privKey_serialized:               " << master_privKey_serialized_str << std::endl;
    std::cout << "master_pubKey_serialized:                " << master_pubKey_serialized_str << std::endl;
    std::cout << "master_pubKey_addressP2WPKH:             " << master_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_privKey_serialized:             " << child_84_privKey_serialized_str << std::endl;
    std::cout << "child_84_pubKey_serialized:              " << child_84_pubKey_serialized_str << std::endl;
    std::cout << "child_84_pubKey_addressP2WPKH:           " << child_84_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_privKey_serialized:          " << child_84_0h_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_pubKey_serialized:           " << child_84_0h_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_pubKey_addressP2WPKH:        " << child_84_0h_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_privKey_serialized:       " << child_84_0h_0h_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_pubKey_serialized:        " << child_84_0h_0h_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_pubKey_addressP2WPKH:     " << child_84_0h_0h_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_0_privKey_serialized:     " << child_84_0h_0h_0_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_pubKey_serialized:      " << child_84_0h_0h_0_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_pubKey_addressP2WPKH    " << child_84_0h_0h_0_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;
    std::cout << "child_84_0h_0h_0_0_privKey_serialized:   " << child_84_0h_0h_0_0_privKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_0_pubKey_serialized:    " << child_84_0h_0h_0_0_pubKey_serialized_str << std::endl;
    std::cout << "child_84_0h_0h_0_0_pubKey_addressP2WPKH  " << child_84_0h_0h_0_0_pubKey_addressP2WPKH << std::endl;
    std::cout << std::endl;

    if (strcmp(child_84_0h_0h_0_0_pubKey_addressP2WPKH.c_str(), TARGET_ADDRESS) == 0){
        return 1;
    }
    return 0;
}

int main(){
    loopCombinations(KNOWN_WORDS, 0, N_WORDS);
    return 0;
}
