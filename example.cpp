#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <iostream>
#include <vector>
#include <fstream>

using namespace libff;
using std::size_t;

template<typename FieldT, typename GroupT>
void test_add(const std::string& filename)
{

  std::ofstream ofile(filename);
  FieldT elem1 = FieldT::random_element();
  FieldT elem2 = FieldT::random_element();

  GroupT g1 = elem1*GroupT::one();
  GroupT g2 = elem2*GroupT::one();
  GroupT g3 = g1 + g2;
  GroupT g4 = (elem1 + elem2) * GroupT::one();
  ofile << g1 << g2 << g3 << g4;

  std::cout << g1 << "\n" << g2 << "\n" << g3 << "\n" << g4 << "\n";
}

template<typename FieldT, typename GroupT>
void test_read(const std::string& filename)
{
  GroupT g1, g2, g3, g4;
  std::ifstream ifile(filename);

  ifile >> g1 >> g2 >> g3 >> g4;
  std::cout << g1 << "\n" << g2 << "\n" << g3 << "\n" << g4 << "\n";
}


int main(int argc, char *argv[])
{
    alt_bn128_pp::init_public_params();
    typedef G1<alt_bn128_pp> GrpT;
    typedef Fr<alt_bn128_pp> FrT;
    test_add<FrT, GrpT>("write-elems.txt");
    test_read<FrT, GrpT>("write-elems.txt");
    return 0;
} 
  

