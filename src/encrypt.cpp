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

struct grcy_mpi_rational
{
    int Sign;
    gcry_mpi_t Numerator;
    gcry_mpi_t Denominator;
};


static void rat_approx(double f, int64_t md, int64_t *num, int64_t *denom)
{
	/*  a: continued fraction coefficients. */
	int64_t a, h[3] = { 0, 1, 0 }, k[3] = { 1, 0, 0 };
	int64_t x, d, n = 1;
	int i, neg = 0;
 
	if (md <= 1) { *denom = 1; *num = (int64_t) f; return; }
 
	if (f < 0) { neg = 1; f = -f; }
 
	while (f != floor(f)) { n <<= 1; f *= 2; }
	d = f;
 
	/* continued fraction and check denominator each step */
	for (i = 0; i < 64; i++) {
		a = n ? d / n : 0;
		if (i && !a) break;
 
		x = d; d = n; n = x % n;
 
		x = a;
		if (k[1] * a + k[0] >= md) {
			x = (md - k[0]) / k[1];
			if (x * 2 >= a || k[1] >= md)
				i = 65;
			else
				break;
		}
 
		h[2] = x * h[1] + h[0]; h[0] = h[1]; h[1] = h[2];
		k[2] = x * k[1] + k[0]; k[0] = k[1]; k[1] = k[2];
	}
	*denom = k[1];
	*num = neg ? -h[1] : h[1];
}


// calculate ciphertext: c = fmod((x_n/x_d)^(rx*(p-1)+1),p*q)
static grcy_mpi_rational encrypt (double value, gcry_mpi_t p, gcry_mpi_t q)
{
    double v = value;
    
    // calculate N=p*q
    gcry_mpi_t N = gcry_mpi_new(gcry_mpi_get_nbits(p)+gcry_mpi_get_nbits(q));
    gcry_mpi_mul (N, p, q);
    
    struct grcy_mpi_rational cipher;
    cipher.Sign = boost::math::signbit(v);
    cipher.Numerator = gcry_mpi_new (0);
    cipher.Denominator = gcry_mpi_new (0);

    if (v < 0)
        v *= -1.0;

    // calculate x_n and x_d
	int64_t d, n;
    rat_approx(v, 100000000, &n, &d);
    std::stringstream v_n, v_d;
    v_n << std::hex << n;
    v_d << std::hex << d;
    
        
    gcry_mpi_t x_n = gcry_mpi_new(0);
    gcry_mpi_t x_d = gcry_mpi_new(0);
    size_t scanned;
    gcry_mpi_scan(&x_n, GCRYMPI_FMT_HEX, v_n.str().c_str(), 0, &scanned);
    gcry_mpi_scan(&x_d, GCRYMPI_FMT_HEX, v_d.str().c_str(), 0, &scanned);
    
    // calculate e = (rx*(p-1)+1)
    gcry_mpi_t e = gcry_mpi_new (0);
    gcry_mpi_sub (e, p, GCRYMPI_CONST_ONE); // p-1
    gcry_mpi_mul (e, e, GCRYMPI_CONST_ONE); // rx*(p-1): should be random, here simply rx=1
    gcry_mpi_add (e, e, GCRYMPI_CONST_ONE); // (rx*(p-1)+1)
    
    // calculate fmod((x_n)^e, N)
    gcry_mpi_powm (cipher.Numerator, x_n, e, N); 
    
    // calculate fmod((x_d)^e, N)
    gcry_mpi_powm (cipher.Denominator, x_d, e, N); 
    
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
        ciphertext["sign"] = cipher.Sign;
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