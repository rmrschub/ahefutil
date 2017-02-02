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
        int signA = ciphertext_A["sign"].get<int>();
        std::string numAStr = ciphertext_A["numerator"];
        std::string denomAStr = ciphertext_A["denominator"];
        gcry_mpi_t numA, denomA;
        numA = gcry_mpi_new(0);
        denomA = gcry_mpi_new(0);
        gcry_mpi_scan(&numA, GCRYMPI_FMT_HEX, numAStr.c_str(), 0, &scanned);
        gcry_mpi_scan(&denomA, GCRYMPI_FMT_HEX, denomAStr.c_str(), 0, &scanned);
        
        
        // read ciphertext from ENCRYPTED_B
        nlohmann::json ciphertext_B;
        std::ifstream encryptedBStream(vm["ENCRYPTED_B"].as<std::string>());
        encryptedBStream >> ciphertext_B;
        encryptedBStream.close();
        int signB = ciphertext_B["sign"].get<int>();
        std::string numBStr = ciphertext_B["numerator"];
        std::string denomBStr = ciphertext_B["denominator"];
        gcry_mpi_t numB, denomB;
        numB = gcry_mpi_new(0);
        denomB = gcry_mpi_new(0);
        gcry_mpi_scan(&numB, GCRYMPI_FMT_HEX, numBStr.c_str(), 0, &scanned);
        gcry_mpi_scan(&denomB, GCRYMPI_FMT_HEX, denomBStr.c_str(), 0, &scanned);
        
        // add encrypted numbers: E(x+y) = fmod( E(x)+E(y), N)
        
//TODO:        int signC = signA * signB
        
        gcry_mpi_t numC = gcry_mpi_new (0);
        gcry_mpi_t denomC = gcry_mpi_new (0);
        gcry_mpi_t t1 = gcry_mpi_new (0);
        gcry_mpi_t t2 = gcry_mpi_new (0);
        gcry_mpi_t t3 = gcry_mpi_new (0);
        
        gcry_mpi_mul (t1, numA, denomB);
        gcry_mpi_mul (t2, numB, denomA);
        
        gcry_mpi_add (numC, t1, t2);
        gcry_mpi_mul (denomC, denomA, denomB);
        
        gcry_mpi_mod(numC, numC, N);
        gcry_mpi_mod(denomC, denomC, N);
        
        
        // write ENCRYPTED_C to file
        nlohmann::json ciphertext_C;
        ciphertext_C["sign"] = signB;
        ciphertext_C["numerator"] = toString(numC);
        ciphertext_C["denominator"] = toString(denomC);
        time_t t;
        time(&t);
        ciphertext_C["created"] = ctime(&t);
        
        std::string outFile = vm["output"].as<std::string>();
        std::ofstream ofs (outFile, std::ofstream::out);
        ofs << std::setw(4) << ciphertext_C << std::endl;
        ofs.close();
        
        
        // cleanup
        gcry_mpi_release(N);
        gcry_mpi_release(numA);
        gcry_mpi_release(denomA);
        gcry_mpi_release(numB);
        gcry_mpi_release(denomB);
        gcry_mpi_release(t1);
        gcry_mpi_release(t2);
        gcry_mpi_release(t3);
        gcry_mpi_release(numC);
        gcry_mpi_release(denomC);
        
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