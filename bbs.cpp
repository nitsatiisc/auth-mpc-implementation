#include "bbs.hpp"
#include "randomness.hpp"

using namespace libff;
using std::size_t;

int main(int argc, char *argv[])
{
    alt_bn128_pp::init_public_params();
    typedef alt_bn128_pp ppT;
	typedef Fr<ppT> FieldT;

	// benchmark FieldT operations
	std::vector<FieldT> elems;
	std::cout << "Generating random elements" << std::endl;
	for(size_t i=0; i < 1000000; ++i)
			elems.emplace_back(FieldT::random_element());
	std::cout << "Generated random elements" << std::endl;

	// compute product of all the elements
	auto start = libff::get_nsec_time();
	FieldT accum = FieldT::one();
	for(size_t i=0; i < 1000000; ++i)
			accum = accum * elems[i];

	auto end = libff::get_nsec_time();
	std::cout << "1000000 F-mults took " << (end - start)/1000000 << " ms" << std::endl;
	return 0;



    testReadAndWrite<ppT>();
    testSignAndVerify<ppT>();

    FSModule<Fr<ppT>> fs;
    std::vector<uint64_t> msg = {23, 25, 88};
    fs.absorb(msg);
    Fr<ppT> r = fs.squeeze();
    std::cout << "r = " << r << std::endl;

    FSModule<Fr<ppT>> fs1;
    fs1.absorb(msg);
    Fr<ppT> r1 = fs1.squeeze();
    std::cout << "r1 = " << r1 << std::endl;

    
    return 0;
}
