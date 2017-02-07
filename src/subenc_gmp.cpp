/*
 *  ahefutil addenc -a cipherA.json -b cipherB.json -p public_key.json -o cipherC.json
 *
 *  Add two encrypted numbers together and write to file
 *
 */

#define _OPEN_SYS_ITOA_EXT
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <cmath>
#include <limits>
#include <algorithm>
#include <boost/math/special_functions/sign.hpp>
#include "json.hpp"
#include "boost/program_options.hpp" 

#include <gmp.h>

namespace 
{ 
  const size_t ERROR_IN_COMMAND_LINE = 1; 
  const size_t SUCCESS = 0; 
  const size_t ERROR_UNHANDLED_EXCEPTION = 2; 
 
} // namespace 



static void smod (mpz_t a, mpz_t p)
{
    if (mpz_sgn(a) < 0)
    {
        mpz_abs(a,a);
        mpz_mod(a, a, p);
        mpz_neg(a, a);    
    }
    else
    {
        mpz_mod(a, a, p);
    }
}


int main(int argc, char** argv)
{
    try 
    {
        namespace po = boost::program_options;
        po::options_description description("Usage");
        description.add_options()
            ("help,h", "Display this help message") 
            ("ENCRYPTED_A,a", po::value<std::string>()->required(), "File containing ENCRYPTED_A.")
            ("ENCRYPTED_B,b", po::value<std::string>()->required(), "File containing ENCRYPTED_B.")
            ("publicKey,p", po::value<std::string>()->required(), "File containing public key.")
            ("output,o", po::value<std::string>()->required(), "File containing the encrypted result.");
           
        po::variables_map vm;
        
        try
        {
            po::store(po::command_line_parser(argc, argv).options(description).run(), vm);

            if (vm.count("help")) 
            {
                std::cout << description;
                return SUCCESS; 
            }
            
            po::notify(vm);    
        }
        catch(po::error& e) 
        { 
            std::cerr << "ERROR: " << e.what() << std::endl << std::endl; 
            std::cerr << description << std::endl; 
            return ERROR_IN_COMMAND_LINE; 
        } 
        
    // app code goes here
    
        // read publicKey from file 
        nlohmann::json public_key;
        std::ifstream publicKeyStream(vm["publicKey"].as<std::string>());
        publicKeyStream >> public_key;
        publicKeyStream.close();
        
        mpz_t N;
        mpz_init(N);
        mpz_set_str ( N, public_key["N"].get<std::string>().c_str(), 16 );

        // read ciphertext from ENCRYPTED_A
        nlohmann::json ciphertext_A;
        std::ifstream encryptedAStream(vm["ENCRYPTED_A"].as<std::string>());
        encryptedAStream >> ciphertext_A;
        encryptedAStream.close();
        
        mpz_t a1, b1;
        mpz_init(a1);
        mpz_init(b1);
        mpz_set_str ( a1, ciphertext_A["numerator"].get<std::string>().c_str(), 16 );
        mpz_set_str ( b1, ciphertext_A["denominator"].get<std::string>().c_str(), 16 );

        // read ciphertext from ENCRYPTED_B
        nlohmann::json ciphertext_B;
        std::ifstream encryptedBStream(vm["ENCRYPTED_B"].as<std::string>());
        encryptedBStream >> ciphertext_B;
        encryptedBStream.close();
  
        mpz_t a2, b2;
        mpz_init(a2);
        mpz_init(b2);
        mpz_set_str ( a2, ciphertext_B["numerator"].get<std::string>().c_str(), 16 );
        mpz_set_str ( b2, ciphertext_B["denominator"].get<std::string>().c_str(), 16 );
        
        // add encrypted numbers: E(x+y) = fmod( E(x)+E(y), N)
        mpz_t t1, t2, a3, b3;
        mpz_init (a3);
        mpz_init (b3);
        mpz_init (t1);
        mpz_init (t2);

        mpz_mul(t1, a1, b2);
        mpz_mul(t2, a2, b1);
        mpz_sub(a3, t1, t2);
        smod(a3, N);

        mpz_mul(b3, b1, b2);
        smod(b3, N);
                
        // write ENCRYPTED_C to file
        char *v_n, *v_d;
        gmp_asprintf (&v_n, "%Zx", a3);
        gmp_asprintf (&v_d, "%Zx", b3);
        
        nlohmann::json ciphertext_C;
        ciphertext_C["numerator"] = std::string(v_n);
        ciphertext_C["denominator"] = std::string(v_d);
        time_t t;
        time(&t);
        ciphertext_C["created"] = ctime(&t);
        
        std::string outFile = vm["output"].as<std::string>();
        std::ofstream ofs (outFile, std::ofstream::out);
        ofs << std::setw(4) << ciphertext_C << std::endl;
        ofs.close();
        
    // app code ends here
    
    }
    catch (std::exception& e) 
    { 
        std::cerr << "Unhandled Exception reached the top of main: " 
                  << e.what() 
                  << ", application will now exit" 
                  << std::endl; 

        return ERROR_UNHANDLED_EXCEPTION; 
    } 

    return SUCCESS; 
}