#include "proof_of_work.h"
#include "global.h"
#include "helper.h"
#include "sha256.h"

//Create a nounce string to be appended with challenge string
std::string ProofOfWork::addNounce(uint l = 15, std::string charIndex = "abcdefghijklmnaoqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
{ 
    /* array of random values that will be used to iterate through random indexes of 'charIndex' */
    uint ri[15]; 

    // assigns a random number to each index of "ri"
    for (uint i = 0; i < l; ++i) 
        ri[i] = rand() % charIndex.length();
    
    // random string that will be returned by this function
    std::string rs = ""; 

    // appends a random amount of random characters to "rs"
    for (uint i = 0; i < l; ++i) 
        rs += charIndex[ri[i]];

    // if the outcome is empty, then redo the generation
    if (rs.empty()) addNounce(l, charIndex); 
        //return 1;
    else 
        return rs;

    return 0;    
}

//Generates the challenge string 
std::string ProofOfWork::generateChallenge(uint64_t txn_id){
    string myString = std::to_string(txn_id);
    string output1 = sha256(myString);
    //cout << "Challenge string is: " << output1 << endl;
    return output1;
}

//Append the challenge string with the nounce
std::string ProofOfWork::attemptGenerate(string challenge){

    srand(time(NULL));
    string nonce = addNounce();
    challenge.append(nonce);
    return challenge;
}

//Initiates proof of work on the current transaction 
void ProofOfWork::proofOfWork()
{
    int found = 0; 
    string curr_block_id = createCurrentBlockId();
    string challenge;
    if(block_ledger.size() == 0)
    	challenge = sha256(curr_block_id);
    else
    	challenge = sha256(curr_block_id + block_ledger[block_ledger.size() - 1]);
    while(found != 1){
        challenge = attemptGenerate(challenge);
        challenge = sha256(challenge);
        //cout << "Hash String is : " << challenge << endl;
        if(challenge.compare(0, 3, "000") == 0) {
            found = 1; ;    
        	//cout << "Proof of Work String is : " << challenge << endl;
        	block_ledger.push_back(curr_block_id);
        	/*for (std::vector<string>::iterator it = block_ledger.begin() ; it != block_ledger.end(); ++it)
    			std::cout << ' ' << *it;
  			std::cout << '\n';*/
  			dumpToFile(curr_block_id);
        }
    }
}

//Store the block ids to globalLedger file
void ProofOfWork::dumpToFile(string curr_block_id){
	ofstream globalLedger;
	globalLedger.open("globalLedger.txt", std::ios_base::app);
	//globalLedger << curr_block_id << "\n";
	globalLedger.close();
}

//Store the current transaction id to transactions vector
void ProofOfWork::storeTransactions(uint64_t txn_id)
{
	//bool value = validateTransation;
	if(validateTransaction(txn_id)) {
		cout<<"Storing to array";
		transactions.push_back(txn_id);
	}
}

//Creates the current block id from transaction
std::string ProofOfWork::createCurrentBlockId()
{
    std::string resultStr;
    uint64_t transaction_id = transactions[transactions.size() - 1];
    resultStr = std::to_string(transaction_id);
	std::string hashedStr = sha256(resultStr);
    return hashedStr;
}

//Validate a transaction to check if the transaction id is already been used
bool ProofOfWork::validateTransaction(uint64_t txn_id)
{
	std::vector<uint64_t>::iterator result;
	result = find(transactions.begin(), transactions.end(), txn_id);
	if(result >= transactions.end())
		return true;
	else
		return false;
}
