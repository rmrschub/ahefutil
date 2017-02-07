/*
 *  ahefutil decrypt -p private_keys.json -c cipher.json
 *
 *  Decrypts cipertext as x = D(c) = fmod(c,p) and writes to stdout.
 *
 */

#define _OPEN_SYS_ITOA_EXT
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <fstream>
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


static void die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
}

static std::string toString ( gcry_mpi_t a)
{
    unsigned char *buf;
    size_t bufSize;
    gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, &bufSize, a);
    std::string std_string(reinterpret_cast<const char *>(buf), bufSize-1);
    gcry_free (buf);
    return std_string;
}

struct Cipher
{
    gcry_mpi_t Numerator;
    gcry_mpi_t Denominator;
} cipherText;


int main(int argc, char** argv)
{
    try 
    {
        namespace po = boost::program_options;
        po::options_description description("Usage");
        description.add_options()
            ("help,h", "Display this help message") 
            ("cipherText,c", po::value<std::string>()->required(), "File containing ciphertext.")
            ("privateKeys,p", po::value<std::string>()->required(), "File containing private keys.");
           
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
        
        // initialize MPI subsystem
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        if (! gcry_check_version (GCRYPT_VERSION))
            die ("version mismatch\n");
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);


        // read privateKeys from file 
        nlohmann::json private_keys;
        std::ifstream privateKeysStream(vm["privateKeys"].as<std::string>());
        privateKeysStream >> private_keys;
        privateKeysStream.close();
        
        // parse and construct grcy_mpi_t
        std::string pString = private_keys["p"];
        std::string qString = private_keys["q"];
        gcry_mpi_t p,q;
        size_t scanned;
        p = gcry_mpi_new(0);
        q = gcry_mpi_new(0);
        gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, pString.c_str(), 0, &scanned);
        gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, qString.c_str(), 0, &scanned);

        // read ciphertext from file
        nlohmann::json ciphertext;
        std::ifstream ciphertextStream(vm["cipherText"].as<std::string>());
        ciphertextStream >> ciphertext;
        ciphertextStream.close();
        
        // parse and construct grcy_mpi_t
        std::string denomStr = ciphertext["denominator"];
        std::string numStr = ciphertext["numerator"];
        
        gcry_mpi_t num, denom;
        num = gcry_mpi_new(0);
        denom = gcry_mpi_new(0);
        gcry_mpi_scan(&num, GCRYMPI_FMT_HEX, numStr.c_str(), 0, &scanned);
        gcry_mpi_scan(&denom, GCRYMPI_FMT_HEX, denomStr.c_str(), 0, &scanned);
        
        // decrypt ciphertext: x = D(c) = fmod(c,p) = smod(a,p) / smod(b,p)
        gcry_mpi_t X_n = gcry_mpi_new (0);
        
        if (gcry_mpi_is_neg(num))
        {
            gcry_mpi_abs (num);
            gcry_mpi_mod(X_n, num, p);
            gcry_mpi_neg (X_n, X_n);
        }
        else
        {
            gcry_mpi_mod(X_n, num, p);
        }
        
        
        gcry_mpi_t X_d = gcry_mpi_new (0);
        
        if (gcry_mpi_is_neg(denom))
        {
            gcry_mpi_abs (denom);
            gcry_mpi_mod(X_d, denom, p);
            gcry_mpi_neg (X_d, X_d);
        }
        else
        {
            gcry_mpi_mod(X_d, denom, p);
        }

        // print cleartext to stdout
        gcry_mpi_t gcd = gcry_mpi_new(0);
        gcry_mpi_gcd(gcd, X_n, X_d);
        
        // simplify fraction
        gcry_mpi_t a = gcry_mpi_new(0);
        gcry_mpi_t b = gcry_mpi_new(0);
        gcry_mpi_div (a, NULL, X_n, gcd, 0);
        gcry_mpi_div (b, NULL, X_d, gcd, 0);
        

        mpf_set_default_prec( gcry_mpi_get_nbits(X_n) + gcry_mpi_get_nbits(X_d) );
        mpf_t A, B, C;
        mpf_init_set_str(A, toString(X_n).c_str(), 16);
        mpf_init_set_str(B, toString(X_d).c_str(), 16);
        mpf_init (C);
        
        mpf_div(C, A, B);
        mpf_out_str(0, 10, 30, C);
        
        
/*        
        mpz_t A, B;
        mpz_init (A);
        mpz_init (B);
        mpz_set_str(A, toString(X_n).c_str(), 16);
        mpz_set_str(B, toString(X_d).c_str(), 16);
        
        mpq_t result;
        mpq_init (result);
        mpq_set_num (result, A);
        mpq_set_den (result, B);
        
        mpq_canonicalize (result);
        std::cout << mpq_out_str(0, 10, result) << std::endl;
*/        
        
            /*

        
        std::cout << "#a " << gcry_mpi_get_nbits(X_n)  << std::endl;
        std::cout << "#b " << gcry_mpi_get_nbits(X_d)  << std::endl;
        
        std::cout << "a " << toString(X_n).c_str() << std::endl;
        std::cout << "b " << toString(X_d).c_str() << std::endl;
        
        */

        // cleanup
        gcry_mpi_release(p);
        gcry_mpi_release(q);
        gcry_mpi_release(num);
        gcry_mpi_release(denom);
        gcry_mpi_release(X_n);
        gcry_mpi_release(X_d);
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