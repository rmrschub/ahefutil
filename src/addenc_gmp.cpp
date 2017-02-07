/*
 *  ahefutil addenc -a cipherA.json -b cipherB.json -p public_key.json -o cipherC.json
 *
 *  Add two encrypted numbers together and write to file
 *
 */

#define _OPEN_SYS_ITOA_EXT
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
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


struct grcy_mpi_rational
{
    gcry_mpi_t Numerator;
    gcry_mpi_t Denominator;
};


static std::string toString ( gcry_mpi_t a)
{
    unsigned char *buf;
    size_t bufSize;
    gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, &bufSize, a);
    std::string std_string(reinterpret_cast<const char *>(buf), bufSize-1);
    gcry_free (buf);
    return std_string;
}


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


// add encrypted numbers: E(x+y) = fmod( E(x)+E(y), N)
/*
static mpq_t add (mpq_t a, mpq_t b, mpz_t publicKey)
{
    mpz_t a1, b1, a2, b2, t1, t2, a3, b3;
    mpz_init (a1);
    mpz_init (b1);
    mpz_init (a2);
    mpz_init (b2);
    mpz_init (a3);
    mpz_init (b3);
    mpz_init (t1);
    mpz_init (t2);
    
    mpq_get_num(a1, a);
    mpq_get_den(b1, a);
    
    mpq_get_num(a2, b);
    mpq_get_den(b2, b);
    
    mpz_mul(t1, a1, b2);
    smod(t1, publicKey);
    
    mpz_mul(t2, b1, a2);
    smod(t2, publicKey);
    
    mpz_add(a3, t1, t2);
    smod(a3, publicKey);
    
    mpz_mul(b3, b1, b2);
    smod(b3, publicKey);
    
    mpq_t c;
    mpq_init (c);
    mpq_set_num(c,a3);
    mpq_set_den(c,b3);
    mpq_canonicalize(c);
    
    return c;
}
*/

/*
static void grcy_mpi_smod (gcry_mpi_t a, gcry_mpi_t p)
{
    if (gcry_mpi_is_neg(a))
    {
        std::cout << "smod is neg" << std::endl;
        gcry_mpi_abs(a);
        gcry_mpi_mod(a, a, p);
        gcry_mpi_neg(a, a);    
    }
    else
    {
        std::cout << "smod is pos" << std::endl;
        gcry_mpi_mod(a, a, p);
    }
}
*/

// add encrypted numbers: E(x+y) = fmod( E(x)+E(y), N)
/*
static grcy_mpi_rational add (grcy_mpi_rational a, grcy_mpi_rational b, gcry_mpi_t publicKey)
{
    struct grcy_mpi_rational c;
    
    gcry_mpi_t t1 = gcry_mpi_new (0);
    gcry_mpi_mul (t1, a.Numerator, b.Denominator);
    grcy_mpi_smod(t1, publicKey);
    
    gcry_mpi_t t2 = gcry_mpi_new (0);
    gcry_mpi_mul (t2, b.Numerator, a.Denominator);
    grcy_mpi_smod(t2, publicKey);
    
    std::cout << gcry_mpi_cmp(t1,t2) << std::endl;
    
    gcry_mpi_t t3 = gcry_mpi_new (0);
    gcry_mpi_add (t3, t2, t1);
    grcy_mpi_smod(t3, publicKey);

    c.Numerator = gcry_mpi_new (0);
    gcry_mpi_set(c.Numerator, t3);
        
    c.Denominator = gcry_mpi_new (0);
    gcry_mpi_mul (c.Denominator, a.Denominator, b.Denominator);
    grcy_mpi_smod(c.Denominator, publicKey);
    
    gcry_mpi_release(t1);
    gcry_mpi_release(t2);
    
    return c;
}
*/    



static void die (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  exit (1);
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
    
        // initialize MPI subsystem
        gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
        if (! gcry_check_version (GCRYPT_VERSION))
            die ("version mismatch\n");
        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
        

        // read publicKey from file 
        nlohmann::json public_key;
        std::ifstream publicKeyStream(vm["publicKey"].as<std::string>());
        publicKeyStream >> public_key;
        publicKeyStream.close();
        /*
        std::string publicKeyString = public_key["N"];
        gcry_mpi_t N = gcry_mpi_new(0);
        size_t scanned;
        gcry_mpi_scan(&N, GCRYMPI_FMT_HEX, publicKeyString.c_str(), 0, &scanned);
        */
        
        mpz_t N;
        mpz_init(N);
        mpz_set_str ( N, public_key["N"].get<std::string>().c_str(), 16 );


        // read ciphertext from ENCRYPTED_A
        nlohmann::json ciphertext_A;
        std::ifstream encryptedAStream(vm["ENCRYPTED_A"].as<std::string>());
        encryptedAStream >> ciphertext_A;
        encryptedAStream.close();
        
        /*
        struct grcy_mpi_rational a;
        a.Numerator = gcry_mpi_new(0);
        a.Denominator = gcry_mpi_new(0);
        gcry_mpi_scan(&a.Numerator, GCRYMPI_FMT_HEX, ciphertext_A["numerator"].get<std::string>().c_str(), 0, &scanned);
        gcry_mpi_scan(&a.Denominator, GCRYMPI_FMT_HEX, ciphertext_A["denominator"].get<std::string>().c_str(), 0, &scanned);
        */
        
        
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
        
        /*
        struct grcy_mpi_rational b;
        b.Numerator = gcry_mpi_new(0);
        b.Denominator = gcry_mpi_new(0);
        gcry_mpi_scan(&b.Numerator, GCRYMPI_FMT_HEX, ciphertext_B["numerator"].get<std::string>().c_str(), 0, &scanned);
        gcry_mpi_scan(&b.Denominator, GCRYMPI_FMT_HEX, ciphertext_B["denominator"].get<std::string>().c_str(), 0, &scanned);
        */
        
        mpz_t a2, b2;
        mpz_init(a2);
        mpz_init(b2);
        mpz_set_str ( a2, ciphertext_B["numerator"].get<std::string>().c_str(), 16 );
        mpz_set_str ( b2, ciphertext_B["denominator"].get<std::string>().c_str(), 16 );

        
        
        
        // add encrypted numbers: E(x+y) = fmod( E(x)+E(y), N)
        
        //struct grcy_mpi_rational c = add(a,b,N);
        mpz_t t1, t2, a3, b3;
        mpz_init (a3);
        mpz_init (b3);
        mpz_init (t1);
        mpz_init (t2);

        mpz_mul(t1, a1, b2);
//        smod(t1, N);

        mpz_mul(t2, a2, b1);
//        smod(t2, N);

        mpz_add(a3, t1, t2);
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
        
        
        // cleanup
        //gcry_mpi_release(N);

        
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