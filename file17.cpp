/*
  LibCatena - a simple blockchain implementation in C++
  https://github.com/mohaps/libcatena
  
  Copyright 2018 Saurav Mohapatra. 

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
#include "catena/Commons.hpp"
#include "catena/Hash.hpp"
#include "catena/NonceFinder.hpp"
#include "catena/Block.hpp"
#include "catena/BlockChain.hpp"


namespace catena {
class Main {
public:
  static void testNonceFinder() {

      std::string input = Hash::sha256("LibCatena by Saurav Mohapatra (mohaps@gmail.com)");
      size_t difficulty = 5;
      std::cout << "Trying to find nonce ..." << std::endl;
      std::cout << "  Input => \""<<input<<"\"" << std::endl;
      std::cout << "  Difficulty => "<< difficulty << std::endl;
      NonceFinder finder(input, difficulty);
      auto result = finder.find();
      if (result.first) {
        std::cout << "!!! Found Result (elapsed: "<< finder.getClock().elapsedSeconds()<< " seconds). hash = " << result.second.first << " nonce = " << result.second.second << std::endl;
      } else {
        throw std::runtime_error("could not find a valid nonce!");
      }
  }

  static void testMerkle() {
    std::vector<std::string> inputs {
      "Block 1",
      "Block 2",
      "Block 3",
      "Block 4",
      "Block 5"
    };
    // round 1
    std::string h_0_1 = Hash::merkle2(inputs[0], inputs[1]);
    std::string h_2_3 = Hash::merkle2(inputs[2], inputs[3]); 
    std::string h_4 = Hash::merkle1(inputs[4]);
    std::string h_0_3 = Hash::merkle2(h_0_1, h_2_3);

    std::string hRoot = Hash::merkle2(h_0_3, Hash::merkle1(h_4));
    std::cout << "Merkle Root (Unrolled) => \""<<hRoot<<"\"" << std::endl;
    SystemClock clock;
    std::string merkleRoot = Hash::merkle(inputs);
    std::cout << "Merkle Root (computed in "<<clock.elapsedMicros()<<" usecs) =>\"" << merkleRoot << "\"" << std::endl;
    if (hRoot == merkleRoot) {
      std::cout << "**** merkle root computation is valid!" << std::endl;
    } else {
      throw std::runtime_error("merkle root computation is invalid!");
    }
    
  }

  static void testBlockChain() {
    BlockChain blockChain("Catena Test", 6);
    blockChain.dump(std::cout);
    Scope scope("Catena_Basic_Blockchain");
    for (auto i = 1; i < 10; i++) {
      std::ostringstream os;
      os << "Block #" << i;
      std::string blockData = os.str();

      std::cout << "... Mining for block #" << i << "..." << std::endl;
      Scope scope(blockData, "Blockchain", 2);
      auto b = blockChain.newBlock({blockData}); 
      std::cout << "*** Block #"<<i<<" added to blockchain!" << std::endl;
      b->dump(std::cout);
      std::cout << "!---------------------------------------------------------------!" << std::endl;
    }
    std::cout << "... final blockchain ..." << std::endl;
    blockChain.dump(std::cout);
  }

  static void run(int argc, char** argv) {
    testBlockChain();
  }

};
}

int main(int argc, char** argv) {
  try {
    catena::Main::run(argc, argv);
  } catch (std::exception& ex) {
    std::cerr << "[error] " << ex.what() << std::endl;
    return -1;
  }
  return 0;
}
