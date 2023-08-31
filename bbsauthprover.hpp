#ifndef __AUTH_MPC_BBSAUTHPROVER__
#define __AUTH_MPC_BBSAUTHPROVER__

#include "pokprover.hpp"

template<typename GroupT, typename FieldT, size_t n>
class BBSAuthProver {
    public:
    BBSAuthProver(
        const std::string& hub_address,
        size_t client_id
    ): hub_address(hub_address), client_id(client_id) {
        total_bytes_sent = 0;
    };

    size_t get_communication() { return total_bytes_sent; };

    // needed only for authenticating prover
    void set_signature(const GroupT A, const FieldT e, const FieldT s)
    {
        this->A = A;
        this->e = e;
        this->s = s;
    };

    // needed only for authenticating prover
    void set_message(const std::vector<FieldT>& m)
    {
        this->m = m;
    };

    // needed only for authenticating prover
    void set_randomisation(const FieldT u, const FieldT r, const FieldT eta)
    {
        this->u = u;
        this->r = r;
        this->eta = eta;
        this->v = this->u.inverse();
        this->t = this->s - (this->r)*(this->v);
    };

    // needed only for authenticating prover
    void write_extended_witness(const std::string& filename)
    {
        std::ofstream ofile(filename);
        for(size_t i=0; i < m.size(); ++i)
            ofile << m[i] << "\n";

        ofile << this->eta << "\n";
        ofile << this->r << "\n";
        ofile << this->v << "\n";
        ofile << this->e << "\n";
        ofile << this->t << "\n";

        ofile.close();
    };

    void set_bbs_generators(const std::vector<GroupT>& gens)
    {
        bbsg1 = gens[0]; // g1
        bbsh.clear();
        bbsh.insert(bbsh.end(), gens.begin()+1, gens.end()); // h0,...,hL
        L = bbsh.size() - 1;
    };

    // needed only for authenticating prover
    void compute_statements()
    {
        // compute b = h_0^s. h_1.m_1 + ... h_L.m_L
        GroupT b1 = multi_exp<GroupT, FieldT, multi_exp_method_bos_coster>(
            bbsh.cbegin()+1, bbsh.cend(),
            m.cbegin(), m.cend(),
            1
        );

        b = (s*bbsh[0]) + b1;
        d = (u*b) - (r * bbsh[0]);
        Adash = u*A;
        Abar = (u*b) - (e*Adash);
        D = (eta * bbsh[0]) + b1;
        C = (t - eta)*bbsh[0] - (v*d);
        std::cout << "D:" << D << std::endl;
        // Generators and commitment for proof 1
        // std::vector<GroupT> gens1 = bbsh;
        // dprover1.init();
        // dprover1.set_generators(gens1);
        // dprover1.set_commitment(D);

        // Generators and witness for proof 2


        // Generators and witness for proof 3

    };


    // initialize bulletin board
    void init()
    {
        bb.set_channel(BroadcastChannel(hub_address, client_id));
        bb.init();
    };

    // send statement
    void send_statement(size_t prover_id)
    {
        std::vector<GroupT> statement(4, GroupT::zero());
        if (client_id == prover_id)
        {
            statement[0] = C;
            statement[1] = D;
            statement[2] = (Abar - d);
            statement[3] = Adash;
        }

        std::stringstream msg_statement;
        msg_statement << statement[0] << statement[1] << statement[2] << statement[3];
        bb.publish(msg_statement.str());
        total_bytes_sent += msg_statement.str().size();
    };

    std::vector<GroupT> get_statements()
    {
        std::string msg_statement = bb.get_all_messages();
        std::stringstream msg_stream(msg_statement);
        std::vector<GroupT> statements;
        GroupT elem;
        while (msg_stream >> elem)
            statements.emplace_back(elem);
        
        return statements;
    };

    
    bool run_signature_proof(size_t prover_id)
    {
        if (client_id == prover_id)
            compute_statements();
        
        // initialize hub connections
        init();

        // send statement to all (C, D, Abar/d, Adash) 
        std::cout << "Sending statement for BBS proof" << std::endl;
        send_statement(prover_id);
        // receive all statements
        std::vector<GroupT> statements = get_statements();
        std::cout << "Received all statements" << std::endl;
        assert(statements.size() == 4*n);

        // set generators and statement for the first prover
        dprover1.init();
        dprover1.set_generators(bbsh);
        dprover1.set_coefficients({3, -3, 1});
        //dprover1.set_coefficients({5,-10,10,-5,1});
        dprover1.set_commitment(statements[4*prover_id + 1]);

        // witness file:
        // m_1,...m_L, eta, r, v, e, t

        // next run the dprover1
        std::string shares_file = std::string("Persistence/Transactions-P") + std::to_string(client_id)+".data";
        std::ifstream ifile(shares_file, std::ios::binary);
        auto witness = read_elements_montgomery<FieldT>(ifile);

        std::cout << "Finished reading shares" << witness.size() << std::endl;

        std::vector<FieldT> wit1;

        wit1.emplace_back(witness[L]); // share of eta
        wit1.insert(wit1.end(), witness.begin(), witness.begin()+L);
        dprover1.set_witness(wit1);

        std::cout << "Finished setting witness" << std::endl;

        dprover1.set_bulletin_board(bb);
        Transcript tr = dprover1.run_prover();
        //PoKProof<GroupT, FieldT, n> proof = dprover1.transcript_to_proof(tr, L+1);
        total_bytes_sent += dprover1.get_communication();
        bool ret = dprover1.get_result();
        // run DPOK Verifier

        /* 
        std::cout << "Verifying DPOK" << std::endl;

        DPoKVerifier<GroupT, FieldT, n> verifier;
        verifier.set_generators(bbsh);
        verifier.set_coefficients(std::vector<FieldT>({3, -3, 1}));
        verifier.set_commitment(statements[4*prover_id + 1]);
        bool ret = verifier.verify(proof);
        */        

        if (ret)
            std::cout << "Verification Status [OK]";
        else
            std::cout << "Verification Status [FAIL]";


        // verify C + D = 0 - bbsg1

        return ret;
    };




    private:
    DPoKProver<GroupT, FieldT, n> dprover1, dprover2, dprover3;
    std::string hub_address;
    size_t client_id;
    size_t total_bytes_sent;
    size_t L;
    GroupT A;
    FieldT e,s;
    FieldT u, r, eta;
    GroupT bbsg1;
    std::vector<GroupT> bbsh;
    std::vector<FieldT> m;
    BulletinBoard<BroadcastChannel> bb;
    GroupT Adash, Abar, b, d;
    FieldT v, t;
    GroupT D, C;

};


// Step 1: prepare file
// BBSAuthProver
// set_message()
// set_generators()
// set_signature()
// set_randomisation()
// write_extended_witness()

// RUN MPC (SPDZ)

// Run DPOK
// BBSAuthProver
// set_generators()
// init()
// run_signature_proof()

#endif