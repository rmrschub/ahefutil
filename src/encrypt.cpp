/*
 *  ahefutil encrypt -o cipher.json -p private_keys.json -v 5000
 *
 *  Encrypts given rationalValue and writes ciphertext c = fmod((x_n/x_d)^(rx*(p-1)+1),p*q) to file.
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
#include <stdint.h>

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


static void grcy_mpi_smod (gcry_mpi_t a, gcry_mpi_t p)
{
        if (gcry_mpi_is_neg(a))
    {
        gcry_mpi_abs(a);
        gcry_mpi_mod(a, a, p);
        gcry_mpi_neg(a, a);    
    }
    else
    {
        gcry_mpi_mod(a, a, p);
    }
}

struct grcy_mpi_rational
{
    gcry_mpi_t Numerator;
    gcry_mpi_t Denominator;
};


// calculate ciphertext: c = fmod((x_n/x_d)^(rx*(p-1)+1),p*q)
static grcy_mpi_rational encrypt (double value, gcry_mpi_t p, gcry_mpi_t q)
{
    // get fractional approximation value = numerator/denominator
    mpf_set_default_prec (1024);
    
    mpf_t V;
    mpf_init(V);
    mpf_set_d(V,value);
    
    mpq_t fractional;
    mpq_init (fractional);
    mpq_set_f(fractional,V);
    mpq_canonicalize(fractional);
    
    mpz_t numerator, denominator;
    mpz_init(numerator);
    mpz_init(denominator);
    mpq_get_num(numerator, fractional);
    mpq_get_den(denominator, fractional);
    
    char *v_n, *v_d;
    gmp_asprintf (&v_n, "%Zx", numerator);
    gmp_asprintf (&v_d, "%Zx", denominator);        
    
    // calculate N=p*q
    gcry_mpi_t N = gcry_mpi_new(gcry_mpi_get_nbits(p)+gcry_mpi_get_nbits(q));
    gcry_mpi_mul (N, p, q);

    
    // construct grcy_mpi_rational
    struct grcy_mpi_rational cipher;
    cipher.Numerator = gcry_mpi_new (0);
    cipher.Denominator = gcry_mpi_new (0);

    gcry_mpi_t x_n = gcry_mpi_new(0);
    gcry_mpi_t x_d = gcry_mpi_new(0);
    size_t scanned;

    gcry_mpi_scan(&x_n, GCRYMPI_FMT_HEX, v_n, 0, &scanned);
    gcry_mpi_scan(&x_d, GCRYMPI_FMT_HEX, v_d, 0, &scanned);

    // calculate e = (rx*(p-1)+1)
    gcry_mpi_t e = gcry_mpi_new (0);
    gcry_mpi_sub (e, p, GCRYMPI_CONST_ONE); // p-1
    gcry_mpi_mul (e, e, GCRYMPI_CONST_ONE); // rx*(p-1): should be random, here simply rx=1
    gcry_mpi_add (e, e, GCRYMPI_CONST_ONE); // (rx*(p-1)+1)
    
    
    // calculate smod((x_n)^e, N)
    if (gcry_mpi_is_neg(x_n))
    {
        gcry_mpi_abs(x_n);
        gcry_mpi_powm (cipher.Numerator, x_n, e, N); 
        gcry_mpi_neg (cipher.Numerator, cipher.Numerator);
    }
    else 
    {
        gcry_mpi_powm (cipher.Numerator, x_n, e, N); 
    }
    
    gcry_mpi_powm (cipher.Denominator, x_d, e, N);
    grcy_mpi_smod(cipher.Denominator, N);
    
        
    // cleanup
    gcry_mpi_release(N);
    gcry_mpi_release(x_n);
    gcry_mpi_release(x_d);
    gcry_mpi_release(e);

    return cipher;
}




int main(int argc, char** argv)
{
    try 
    {
        namespace po = boost::program_options;
        po::options_description description("Usage");
        description.add_options()
            ("help,h", "Display this help message") 
            ("outputFile,o", po::value<std::string>()->required(), "Output file containing generated private keys.")
            ("privateKeys,p", po::value<std::string>()->required(), "Private key file.")
            ("value,v", po::value<double>()->required(), "Rational number to encrypt.");
           
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
        std::string inFile = vm["privateKeys"].as<std::string>();
        std::ifstream ifs(inFile);
        ifs >> private_keys;
        ifs.close();
        
        // parse and construct grcy_mpi_t
        std::string pString = private_keys["p"];
        std::string qString = private_keys["q"];
        gcry_mpi_t p,q;
        size_t scanned;
        p = gcry_mpi_new(0);
        q = gcry_mpi_new(0);
        gcry_mpi_scan(&p, GCRYMPI_FMT_HEX, pString.c_str(), 0, &scanned);
        gcry_mpi_scan(&q, GCRYMPI_FMT_HEX, qString.c_str(), 0, &scanned);
        

        grcy_mpi_rational cipher = encrypt (vm["value"].as<double>(), p, q);


        // write ciphertext to output file
        nlohmann::json ciphertext;
        //ciphertext["sign"] = cipher.Sign;
        ciphertext["numerator"] = toString(cipher.Numerator);
        ciphertext["denominator"] = toString(cipher.Denominator);
        time_t t;
        time(&t);
        ciphertext["created"] = ctime(&t);
        
        std::string outFile = vm["outputFile"].as<std::string>();
        std::ofstream ofs (outFile, std::ofstream::out);
        ofs << std::setw(4) << ciphertext << std::endl;
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