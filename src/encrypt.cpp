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


struct Fraction
{
    int Sign;
    int WholePart;
    int Numerator;
    int Denominator;
} fractionalValue;

struct Cipher
{
    int Sign;
    gcry_mpi_t Numerator;
    gcry_mpi_t Denominator;
} cipherText;

/*
 *  DOUBLE CHECK!
 */ 
bool DecimalToFraction(double DecimalNum, Fraction &Result)
{
    Result.Sign = boost::math::signbit(DecimalNum);
    
    if (Result.Sign)
        DecimalNum *= -1.0;
    
    const int MaxIntDigits = std::numeric_limits<int>::digits10;
    const int WholeDigits = int(log10(DecimalNum));
    const int FractionDigits = std::min(std::numeric_limits<double>::digits10 - WholeDigits, MaxIntDigits-1);

    //If number has too many digits, can't convert
    if(WholeDigits > MaxIntDigits)
    {
        return false;
    }

    //Separate into whole part and fraction
    double WholePart;
    DecimalNum = modf(DecimalNum, &WholePart);
    Result.WholePart = int(WholePart);

    //Convert the decimal to a fraction
    const double Denominator = pow(10.0, FractionDigits);
    Result.Numerator = int((DecimalNum * Denominator) + 0.5);
    Result.Denominator = int(Denominator);

    //Return success
    return true;
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
        
        // calculate publicKey N=P*Q
        gcry_mpi_t n = gcry_mpi_new(gcry_mpi_get_nbits(p)+gcry_mpi_get_nbits(q));
        gcry_mpi_mul (n, p, q);

        // convert cleartext value into integral and fractional part
        DecimalToFraction(vm["value"].as<double>(), fractionalValue);
        std::stringstream streamD,streamN;
        streamD << std::hex << (unsigned int)fractionalValue.Denominator;
        std::string x_denom_str( streamD.str() );
        streamN << std::hex << (unsigned int)(fractionalValue.WholePart * fractionalValue.Denominator + fractionalValue.Numerator);
        std::string x_nom_str( streamN.str() );
        
        // prepare ciphertext
        gcry_mpi_t x_n, x_d;
        x_n = gcry_mpi_new(0);
        x_d = gcry_mpi_new(0);
        gcry_mpi_scan(&x_n, GCRYMPI_FMT_HEX, x_nom_str.c_str(), 0, &scanned);
        gcry_mpi_scan(&x_d, GCRYMPI_FMT_HEX, x_denom_str.c_str(), 0, &scanned);
        
        // calculate ciphertext: c = fmod((x_n/x_d)^(rx*(p-1)+1),p*q)
        cipherText.Sign = fractionalValue.Sign;
        
        gcry_mpi_t e = gcry_mpi_new (0);
        gcry_mpi_sub (e, p, GCRYMPI_CONST_ONE); // p-1
        gcry_mpi_mul (e, e, GCRYMPI_CONST_ONE); // rx*(p-1)
        gcry_mpi_add (e, e, GCRYMPI_CONST_ONE); // (rx*(p-1)+1)
        cipherText.Numerator = gcry_mpi_new (0);
        gcry_mpi_powm (cipherText.Numerator, x_n, e, n); // (x_n)^(rx*(p-1)+1)
        cipherText.Denominator = gcry_mpi_new (0);
        gcry_mpi_powm (cipherText.Denominator, x_d, e, n); // fmod( (x_n)^(rx*(p-1)+1) , p*q)

        // write ciphertext to output file
        nlohmann::json ciphertext;
        ciphertext["sign"] = cipherText.Sign;
        ciphertext["numerator"] = toString(cipherText.Numerator);
        ciphertext["denominator"] = toString(cipherText.Denominator);
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
        gcry_mpi_release(n);
        gcry_mpi_release(e);
        gcry_mpi_release(x_n);
        gcry_mpi_release(x_d);
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