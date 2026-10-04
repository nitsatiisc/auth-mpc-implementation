//
// Created by nitin on 17/8/23.
//

#ifndef AUTH_MPC_UTILITY_HPP
#define AUTH_MPC_UTILITY_HPP
#include <iostream>

const char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                          '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};



template<typename T>
std::string ToString(const T& elem)
{
    std::stringstream stream;
    stream << elem;
    return stream.str();
}

std::string hex_string_from_bytes(const unsigned char *bytes, size_t n)
{
    std::string hex_string;
    for(size_t i=0; i < n; ++i)
    {
        uint8_t val = bytes[i];
        hex_string.push_back(hex_table[val/16]);
        hex_string.push_back(hex_table[val % 16]);
    }

    return hex_string;
}

template<typename T>
void print_grp(const std::vector<T> v)
{
    for(size_t i=0; i < v.size(); ++i)
    {
        std::stringstream str;
        str << v[i];
        std::string g = str.str();
        std::string hexg = hex_string_from_bytes((const unsigned char *)(&(g[0])), g.size());
        std::cout << hexg << std::endl;
    }
}

template<typename T>
void read_elements(std::vector<T>& v, const std::string& s, size_t n)
{
    std::stringstream str;
    str << s;

    for(size_t i=0; i < n; ++i)
    {
        str >> v[i];
    }
}


template<typename T>
std::vector<T> read_elements(std::istream& ifile)
{
    std::vector<T> elements;
    T elem;
    while (ifile >> elem)
        elements.emplace_back(elem);

    return elements;
}

template<typename T>
std::vector<T> read_elements(std::istream& ifile, size_t n)
{
    std::vector<T> elements;
    T elem;
    char ch;
    for(size_t i=0; i < n; ++i) {
        ifile >> elem;
        elements.emplace_back(elem);
    }

    return elements;
}

template<typename T>
void write_elements(const std::vector<T>& elems, std::ostream& ofile, size_t count)
{
    assert(elems.size() >= count);
    for(size_t i=0; i < count; ++i) {
        ofile << elems[i];
    }
}

template<typename T>
std::vector<T> read_elements(const std::string& s)
{
    std::vector<T> elements;
    T elem;
    std::stringstream ifile(s);

    while (ifile >> elem)
        elements.emplace_back(elem);

    return elements;
}

template<typename FieldT>
std::vector<FieldT> read_elements_montgomery(std::istream& is)
{
    // precompute powers (2^(8*i)) for i=0,...,31
    std::vector<FieldT> powers_of_two;
    powers_of_two.emplace_back(FieldT::one());
    FieldT power = FieldT::one();
    for(size_t i=0; i < 32; ++i)
    {
        power = FieldT(256)*power;
        powers_of_two.emplace_back(power);
    }

    // Montgomery factor
    size_t nwords = (FieldT::num_bits + 63)/64;
    size_t nbytes = 8 * nwords;
    FieldT R = (FieldT(2))^(64*nwords);
    FieldT Rinv = R.inverse();

    // MP-SPDZ >= 0.3 prefixes Persistence files with a signature
    // (8-byte length + protocol/prime description); skip it if present.
    is.seekg(0, std::ios::end);
    uint64_t file_size = is.tellg();
    is.seekg(0, std::ios::beg);
    uint64_t header_len = 0;
    if (file_size >= 8 && is.read((char *)(&header_len), 8) &&
        header_len < 1024 && file_size >= 8 + header_len &&
        (file_size - 8 - header_len) % nbytes == 0)
        is.seekg(8 + header_len, std::ios::beg);
    else
        is.seekg(0, std::ios::beg);

    std::vector<FieldT> result;
    std::vector<uint8_t> buffer(nbytes);
    size_t count = 0;
    while (!is.eof())
    {
        // read a buffer for the number
        //std::cout << count++ << std::endl;
        is.read((char *)(&buffer[0]), nbytes);
        if (!is.eof())
        {
            FieldT number = 0;
            for(size_t i=0; i < nbytes; ++i)
                number += (FieldT(buffer[i])*powers_of_two[i]);
            number = number * Rinv;
            result.emplace_back(number);
        }
    }

    return result;

}

template<typename FieldT, size_t t, size_t n>
std::vector<FieldT> ShamirShare(const FieldT& s)
{
    std::vector<FieldT> share(n);
    std::vector<FieldT> coefficients;
    coefficients.emplace_back(s);
    for(size_t i=1; i <= t; ++i)
        coefficients.emplace_back(FieldT::random_element());

    for(size_t i=0; i < n; ++i)
    {
        FieldT eval_point = FieldT(i+1);
        FieldT evaluation = FieldT::zero();
        for(size_t j=0; j <= t; ++j)
            evaluation = evaluation + (coefficients[j] * (eval_point^j));

        share[i] = evaluation;

    }

    return share;
}


template<typename FieldT, size_t t, size_t n>
std::vector<std::vector<FieldT>> ShamirShareVec(const std::vector<FieldT>& input)
{
    std::vector<std::vector<FieldT>> shares(n);
    for(size_t i=0; i < input.size(); ++i)
    {
        auto share = ShamirShare<FieldT, t, n>(input[i]);
        for(size_t j=0; j < n; ++j)
            shares[j].emplace_back(share[j]);
    }

    return shares;
}

#endif //AUTH_MPC_UTILITY_HPP
