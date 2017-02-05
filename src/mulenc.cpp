/*
 *  ahefutil mulenc -p public_key.json -a A.enc -b B.enc -o C.enc
 *
 *  Multiply two encrypted numbers and write result to file
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

namespace 
{ 
  const size_t ERROR_IN_COMMAND_LINE = 1; 
  const size_t SUCCESS = 0; 
  const size_t ERROR_UNHANDLED_EXCEPTION = 2; 
 
} // namespace 


struct grcy_mpi_rational
{
    int Sign;
    gcry_mpi_t Numerator;
    gcry_mpi_t Denominator;
};

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

// multiply encrypted numbers: E(x*y) = fmod( E(x)*E(y), N)
static grcy_mpi_rational mul (grcy_mpi_rational a, grcy_mpi_rational b, gcry_mpi_t publicKey)
{
    struct grcy_mpi_rational c;
    c.Numerator = gcry_mpi_new (0);
    c.Denominator = gcry_mpi_new (0);
    
    gcry_mpi_mulm (c.Numerator, a.Numerator, b.Numerator, publicKey);
    gcry_mpi_mulm (c.Denominator, a.Denominator, b.Denominator, publicKey);
    
    if (a.Sign == b.Sign)
    {
        c.Sign = 1;
    }
    else
    {
        c.Sign = -1;
    }

    return c;
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
        std::string publicKeyString = public_key["N"];
        gcry_mpi_t N = gcry_mpi_new(0);
        size_t scanned;
        gcry_mpi_scan(&N, GCRYMPI_FMT_HEX, publicKeyString.c_str(), 0, &scanned);


        // read ciphertext from ENCRYPTED_A
        nlohmann::json ciphertext_A;
        std::ifstream encryptedAStream(vm["ENCRYPTED_A"].as<std::string>());
        encryptedAStream >> ciphertext_A;
        encryptedAStream.close();
        struct grcy_mpi_rational a;
        a.Sign = ciphertext_A["sign"].get<int>();
        a.Numerator = gcry_mpi_new(0);
        a.Denominator = gcry_mpi_new(0);
        gcry_mpi_scan(&a.Numerator, GCRYMPI_FMT_HEX, ciphertext_A["numerator"].get<std::string>().c_str(), 0, &scanned);
        gcry_mpi_scan(&a.Denominator, GCRYMPI_FMT_HEX, ciphertext_A["denominator"].get<std::string>().c_str(), 0, &scanned);
        
        
        // read ciphertext from ENCRYPTED_B
        nlohmann::json ciphertext_B;
        std::ifstream encryptedBStream(vm["ENCRYPTED_B"].as<std::string>());
        encryptedBStream >> ciphertext_B;
        encryptedBStream.close();
        struct grcy_mpi_rational b;
        b.Sign = ciphertext_B["sign"].get<int>();
        b.Numerator = gcry_mpi_new(0);
        b.Denominator = gcry_mpi_new(0);
        gcry_mpi_scan(&b.Numerator, GCRYMPI_FMT_HEX, ciphertext_B["numerator"].get<std::string>().c_str(), 0, &scanned);
        gcry_mpi_scan(&b.Denominator, GCRYMPI_FMT_HEX, ciphertext_B["denominator"].get<std::string>().c_str(), 0, &scanned);
        
        // add encrypted numbers: E(x+y) = fmod( E(x)+E(y), N)
        
        struct grcy_mpi_rational c = mul(a,b,N);
                
        // write ENCRYPTED_C to file
        nlohmann::json ciphertext_C;
        ciphertext_C["sign"] = c.Sign;
        ciphertext_C["numerator"] = toString(c.Numerator);
        ciphertext_C["denominator"] = toString(c.Denominator);
        time_t t;
        time(&t);
        ciphertext_C["created"] = ctime(&t);
        
        std::string outFile = vm["output"].as<std::string>();
        std::ofstream ofs (outFile, std::ofstream::out);
        ofs << std::setw(4) << ciphertext_C << std::endl;
        ofs.close();
        
        
        // cleanup
        gcry_mpi_release(N);

        
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