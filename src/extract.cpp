/*
 *  ahefutil extract -p private_keys.json -o public_key.json
 *
 *  Generates publicKey N=p*q from privateKeys and writes N to file.
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
            ("input,i", po::value<std::string>()->required(), "Input file containing private keys.")
            ("output,o", po::value<std::string>()->required(), "Output file containing generated public key.");
        
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
        std::string inFile = vm["input"].as<std::string>();
        std::ifstream ifs(inFile);
        ifs >> private_keys;
        ifs.close();
        
        // parse private_keys into MPI subsystem
        std::string pString = private_keys["p"];
        std::string qString = private_keys["q"];
        gcry_mpi_t p,q;
        size_t scanned;
        p = gcry_mpi_new(0);
        q = gcry_mpi_new(0);
        gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, pString.c_str(), 0, &scanned);
        gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, qString.c_str(), 0, &scanned);
        
        // calculate publicKey N=p*q
        gcry_mpi_t n = gcry_mpi_new(gcry_mpi_get_nbits(p)+gcry_mpi_get_nbits(q));
        gcry_mpi_mul (n, p, q);
        
        // write to output file
        nlohmann::json public_key;
        public_key["N"] = toString(n);
        time_t t;
        time(&t);
        public_key["created"] = ctime(&t);
        
        std::string outFile = vm["output"].as<std::string>();
        std::ofstream ofs (outFile, std::ofstream::out);
        ofs << std::setw(4) << public_key << std::endl;
        ofs.close();
        
        // cleanup
        gcry_mpi_release(p);
        gcry_mpi_release(q);
        gcry_mpi_release(n);
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