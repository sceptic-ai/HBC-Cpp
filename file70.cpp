//includes
#include <iostream>
#include <ctime>
#include <vector>
#include <string>
#include <tr1/functional>

//namespaces
using namespace std;

//Transaction
struct Transaction{
    //basic transaction data 
    double amount;
    string senderKey;
    string revieverKey;
    time_t timestamp; 
};

//Block
class Block{
    private:
        //index
        int index;
        //all the hash values 
        size_t blockHash;
        size_t prevHash;
        size_t genHash();

    public:
        //constructor 
        Block(int index, Transaction transaction, size_t prevHash); 

        //getters 
        size_t getHash(); 
        size_t getPrevHash(); 
        int getIndex();

        //transaction data member 
        Transaction data; 

        //validate hash

        bool isValid();
};

Block::Block(int idx,Transaction d, size_t prevHash){
    //populate the data with data passed in
    index = idx;
    data = d;
    prevHash = prevHash;
    blockHash = genHash();
}

//return the index
int Block::getIndex(){
    return index;
}

size_t Block::genHash(){
    
    //create a string of all the data 
    string toHash = to_string(data.amount)+ data.revieverKey + data.senderKey + to_string(data.timestamp);

    //create two has vars
    std::tr1::hash<string> toDataHash;
    std::tr1::hash<string> priorHash;
   // std::tr1::hash<size_t> finalH; 

    //xor the two has vars and move it one bit left using the bitwise operator
    return toDataHash(toHash) ^ (priorHash(to_string(prevHash)) << 1);
}

//get the hash 
size_t Block::getHash(){
    return blockHash;
}

//get previous hash
size_t Block::getPrevHash(){
    return prevHash;
}

//check if the hashs match up
bool Block::isValid(){
    return genHash() == blockHash; 
}

//blockchain
class Blockchain{
    private:
        //constructor
        Block createGenBlock();

    public:
        //the chain
        vector<Block> chain;
        Blockchain();

        //funcs 
        void addBlock(Transaction data);
        bool isChainValid();

        //to test demo only this is just to test the security 
        Block *getLatestBlock();

        //print out the data off all blocks on the chain
        void printChain();
};  

Blockchain::Blockchain(){
    //create a genesis block and push it into the chain 
    Block genesisBlock = createGenBlock();
    chain.push_back(genesisBlock);
}

void Blockchain::printChain() {
    //create an interator 
    std::vector<Block>::iterator it;
    
    //iterate through every block on the chain and print its data
    for (it = chain.begin(); it != chain.end(); ++it)
    {
        Block currentBlock = *it;
        printf("\n\nBlock ===================================");
        printf("\nIndex: %d", currentBlock.getIndex());
        printf("\nAmount: %f", currentBlock.data.amount);
        printf("\nSenderKey: %s", currentBlock.data.senderKey.c_str());
        printf("\nReceiverKey: %s", currentBlock.data.revieverKey.c_str());
        printf("\nTimestamp: %ld", currentBlock.data.timestamp);
        printf("\nHash: %zu", currentBlock.getHash());
        printf("\nPrevious Hash: %zu", currentBlock.getPrevHash());
        printf("\nIs Block Valid?: %d", currentBlock.isValid());
    }
}

Block Blockchain::createGenBlock(){
    //create some data for the genesis block
    time_t currTime;
    Transaction d;
    d.amount = 0;
    d.revieverKey = "Gen";
    d.senderKey = "Gen";
    d.timestamp = time(&currTime); 

    //hash the genesis block 
    string toHash = to_string(d.amount)+ d.revieverKey + d.senderKey + to_string(d.timestamp);

    std::tr1::hash<string> toDataHash;
    std::tr1::hash<string> priorHash;
   
    size_t hashy = toDataHash(toHash) ^ (priorHash(to_string(0)) << 1);

    Block genesis(0,d, hashy);

    return genesis; 
}

//DANGER ONLY FOR DEMO PURPOSES
Block *Blockchain::getLatestBlock(){
    return &chain.back();
}

void Blockchain::addBlock(Transaction d){
    //get the index
    int idx = (int)chain.size(); 
    //get the previous has and if prev hash doesnt exist set it to 0
    size_t pHash = (int)chain.size() > 0 ? getLatestBlock()->getHash() : 0;
    //create the block and push to the chain
    Block newBlock(idx, d,pHash);
    chain.push_back(newBlock);
}

bool Blockchain::isChainValid(){
    vector<Block>::iterator it; 

    int chainLen = (int)chain.size();

    for(it = chain.begin(); it != chain.end(); ++it){
        Block currBlock = *it;

        if(!currBlock.isValid()){
            return false;
        }


        if(chainLen > 1){
            Block prevBlock = *(it-1);
            if(currBlock.getPrevHash() != prevBlock.getHash()){
                return false;
            }
        }
    }

    return true; 
}

int main(){
    Blockchain c_block;


    //first block data
    Transaction d1;
    time_t d1Time;
    d1.amount = 1.5; 
    d1.revieverKey = "Jon doe";
    d1.senderKey = "SSPYR0";
    d1.timestamp = time(&d1Time);

    //second block data 
    Transaction d2;
    time_t d2Time;
    d2.amount = 1.8; 
    d2.revieverKey = "Jon doe";
    d2.senderKey = "SSPYR0";
    d2.timestamp = time(&d2Time);

    c_block.addBlock(d1);
    c_block.addBlock(d2);

    c_block.printChain();
}
