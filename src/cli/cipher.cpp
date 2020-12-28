/*
* (C) 2015,2017 Simon Warta (Kullo GmbH)
* (C) 2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_CIPHER_MODES)

#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <sstream>

#if defined(BOTAN_HAS_AEAD)
  #include <botan/aead.h>
#endif

namespace Botan_CLI {

class Cipher final : public Command
   {
   public:
      Cipher() : Command("cipher --buf-size=4096 --decrypt --cipher= --key= --nonce= --ad=") {}

      std::string group() const override
         {
         return "crypto";
         }

      std::string description() const override
         {
         return "Encrypt or decrypt a given file";
         }

      void go() override
         {
         const std::string cipher_algo = get_arg_or("cipher", "");
         const std::string key_hex = get_arg("key");
         const std::string nonce_hex  = get_arg("nonce");
         const std::string ad_hex = get_arg_or("ad", "");
         const size_t buf_size = get_arg_sz("buf-size");

         const std::vector<uint8_t> input = this->slurp_file("-", buf_size);

         const Botan::SymmetricKey key(key_hex);
         const Botan::InitializationVector nonce(nonce_hex);
         const std::vector<uint8_t> ad = Botan::hex_decode(ad_hex);

         auto direction = flag_set("decrypt") ? Botan::Cipher_Dir::DECRYPTION : Botan::Cipher_Dir::ENCRYPTION;

         auto cipher = Botan::Cipher_Mode::create(cipher_algo, direction);
         if(!cipher)
            throw CLI_Error_Unsupported("Cipher algorithm '" + cipher_algo + "' not found");

         // Set key
         cipher->set_key(key);

         // Set associated data
         if(!ad.empty())
            {
#if defined(BOTAN_HAS_AEAD)
            if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(cipher.get()))
               {
               aead->set_ad(ad);
               }
            else
#endif
               {
               throw CLI_Usage_Error("Cannot specify associated data with non-AEAD mode");
               }
            }

         // Set nonce
         cipher->start(nonce.bits_of());

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         cipher->finish(buf);

         write_output(buf);
         }
   };

BOTAN_REGISTER_COMMAND("cipher", Cipher);

}

#endif
