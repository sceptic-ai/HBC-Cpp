#include "Block.h"
#include "Blockchain.h"

using namespace std;

namespace myCoin{

	Blockchain::Blockchain() : size(0), difficulty(3){
		createGenesisBlock();
	}

	Blockchain::~Blockchain(){
		for(Block* blockPtr : chain){
			delete blockPtr;
		}
		chain.clear();
	}

	Blockchain::Blockchain(const Blockchain& rhs){
		for(const Block* blockPtr : rhs.chain){
			Block* currBlock = new Block(*blockPtr);
			chain.push_back(currBlock);
		}
	}

	Blockchain& Blockchain::operator=(const Blockchain& rhs){
		if(this != &rhs){
			for(Block* blockPtr : chain){
				delete blockPtr;
			}
			chain.clear();

			for(const Block* blockPtr : rhs.chain){
				Block* currBlock = new Block(*blockPtr);
				chain.push_back(currBlock);
			}
		}
		return *this;
	}

	void Blockchain::createGenesisBlock(){
		cout << "Creating Genesis Block..." << endl << endl;
		Block* genesisBlock = new Block(0,"0","genesisTrans",0);
		chain.push_back(genesisBlock);
		++size;
	}

	const Block& Blockchain::getLastBlock() const {
		return *(chain[size-1]);
	}

	bool Blockchain::isValidChain() const {
		if(size > 0){
			for(size_t index = 1; index < size; ++index){
				const Block* currBlock = chain[index];
				const Block* prevBlock = chain[index-1];

				if(currBlock->previousHash != prevBlock->blockHash){
					return false;
				}
				if(currBlock->blockHash != currBlock->calculateHash()){
					//cout << currBlock->blockHash << endl << currBlock->calculateHash();
					return false;
				}
			}
		}
		return true;
	}

	void Blockchain::createTransaction(const string& name, double amount){
		mineBlock(name,amount);
	}

	void Blockchain::mineBlock(const string& name, double amount){
		Block lastBlock = getLastBlock();
		Block* newBlock = new Block(size,lastBlock.blockHash,name, amount);


		newBlock->mineBlock(difficulty);
		chain.push_back(newBlock);

		++size;
		cout << "BLOCK SUCCESFULLY MINED..." << endl << endl ;
	}

	void Blockchain::generateBlock(){
		createTransaction("NULL",00000);
	}

	ostream& operator<<(std::ostream& os, const Blockchain& blockchain){
			os << "-------------------------------------------- \n";

		os << "Blockchain has " << blockchain.size-1 << " block(s)" << endl;
		for(const Block* blockPtr : blockchain.chain){
			os << *blockPtr << endl;
			os << "-------------------------------------------- \n";
		}
		return os;
	}

}







