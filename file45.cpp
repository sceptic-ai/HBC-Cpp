#include <iostream>
#include <functional>//for hash
#include <vector>
#include <string>
#define MOD 1000000007
using namespace std;
typedef unsigned long long int  ull;

template<class T>
class Merkle {
	private:
		vector<T> values;
		hash<ull> HASH;
	public:	/*For Copying keep in mind the Algorithm has a serious flaw related to
       		  duplicate txids, resulting in a vulnerability (CVE-2012-2459)
		*/
		Merkle(){
		}
		ull hasher(ull a,ull b){
			1ull * ((HASH(HASH(a)%MOD + HASH(b)%MOD))%MOD);
		}
		int size() {
			return values.size();
		}
		void add(T value) {
			values.push_back(value);
		}
		ull root() {
			vector<ull> current;
			hash<T> hash_T;
			for (auto a:this->values){
				ull h = (hash_T(a) % MOD);
				//cout<<"Hash "<<a<<" = "<<h<<"\n";
				cout<<a<<"   "<<h<<"\n";
				current.push_back(h); //convert to size_t 
			}
			while (current.size() != 1) {
				current = getHashedParents(current);
			}
			return current[0];
		}
	private:
		vector<ull> getHashedParents (const vector<ull> &children) {
			vector <ull> result;
			for (int i=0; i < children.size(); ) {
				ull a = children[i], b = children[i];
				if (++i < children.size()) {
					b = children[i++];
				}
				ull hash = hasher(a,b);
				printf("hash(%d, %d)=>%d \n", a, b, hash);
				result.push_back(hash);
			}
			printf("\n");
			return result;
		}
};
int main() {
	Merkle<string> merkle;
	merkle.add("Hello");
	merkle.add("Merkle");
	merkle.add("Patricia");
	merkle.add("Tree");
	merkle.add("Naive");
	printf("Merkle root hash  = %d\n\n", merkle.root());
	return 0;
}
