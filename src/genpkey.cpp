/*
 *  ahefutil genpkey -o private_keys.json -k 1024
 * 
 * Generate random primes p and q of bitsize k.
 */

#include <gcrypt.h>
#include <fstream>
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
            ("keysize,k", po::value<int>()->default_value(512), "Keysize in bits. Defaults to 512.")
            ("output,o", po::value<std::string>()->required(), "Output file containing generated private keys.");
           
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

        // generate random primes p and q
        int keySize = vm["keysize"].as<int>();
        gcry_error_t err = GPG_ERR_NO_ERROR;
        gcry_mpi_t *factors = NULL;
        gcry_mpi_t p,q = NULL;

        err = gcry_prime_generate (&p,
                                   keySize,
                                   0,
                                   &factors,
                                   NULL, 
                                   NULL,
                                   GCRY_STRONG_RANDOM,
                                   GCRY_PRIME_FLAG_SPECIAL_FACTOR);

        err = gcry_prime_generate (&q,
                                   keySize,
                                   0,
                                   &factors,
                                   NULL, 
                                   NULL,
                                   GCRY_STRONG_RANDOM,
                                   GCRY_PRIME_FLAG_SPECIAL_FACTOR);

        
        // write to output file
        std::string fileName = vm["output"].as<std::string>();
        nlohmann::json private_keys;
        private_keys["p"] = toString(p);
        private_keys["q"] = toString(q);
        time_t t;
        time(&t);
        private_keys["created"] = ctime(&t);

        std::ofstream ofs (fileName, std::ofstream::out);
        ofs << std::setw(4) << private_keys << std::endl;
        ofs.close();
        
        // cleanup
        gcry_mpi_release(p);
        gcry_mpi_release(q);
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