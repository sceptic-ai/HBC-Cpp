#include <iostream>
#include <string>
#include <cstring>
#include <ctime>

using namespace std;

struct data_forSet {
	int id = 0;
	string name = "";
	string family = "";
	string hash = "";
	string PreviousHash = "";
}data_forSet_obj[0x2710];

class block {
	string Hash;
	string PreviousHash;
public:
	static int count;
	struct data {
		int id;
		string name;
		string family;
	}data_obj;

	static string returnRandom() {
		srand(time(0));
		int x = 0;
		x = (rand() % 100) + x;
		return to_string(x);
	}

	//The sha256 will be used in the future 
	static string returnHash(string str) {
		size_t my_hash = hash<string>{}(str);
		string x = to_string(my_hash);
		string rand = returnRandom();
		string finall = x + rand;
		return finall;
	}

	void set(data_forSet *obj) {
		data_obj.id = obj->id;
		data_obj.name = obj->name;
		data_obj.family = obj->family;
		Hash = obj->hash;
		PreviousHash = obj->PreviousHash;
	}

	inline string ReturnHashVariable() {
		return Hash;
	}

	inline string ReturnPreviousHashVariable() {
		return PreviousHash;
	}

	static int SetFromUser() {

		cout << "if u wanna end the input data , put \"end\" to name and family \n";
		do {
			if (count == 0) {
				data_forSet_obj[count].PreviousHash = "000";
			}
			else {
				data_forSet_obj[count].PreviousHash = data_forSet_obj[count - 1].hash;
			}

			data_forSet_obj[count].id = count;

			cout << count + 1 << "-Enter Name :";
			getline(cin, data_forSet_obj[count].name);
			cout << count + 1 << "-Enter Family :";
			getline(cin, data_forSet_obj[count].family);

			data_forSet_obj[count].hash = block::returnHash(data_forSet_obj[count].name + data_forSet_obj[count].family);
			count++;
		} while (data_forSet_obj[count - 1].name != "end" && data_forSet_obj[count - 1].name != "end");
		block::count--;
		return count;
	}

	static void PrintData(block obj[], int count) {
		for (int i = 0; i < count; i++)
		{
			cout << "Id = " << obj[i].data_obj.id + 1 << "\n";
			cout << "Name = " << obj[i].data_obj.name << "\n";
			cout << "Family = " << obj[i].data_obj.family << "\n";
			cout << "Hash = " << obj[i].Hash << "\n";
			cout << "Previous Hash = " << obj[i].PreviousHash << "\n";
			cout << "=========================== \n";
		}
	}

	~block() {
		delete data_forSet_obj;
		free((void*)data_obj.id);
		free((void*)stoi(data_obj.family));
		free((void*)stoi(data_obj.name));
	}
};

int block::count = 0;

int main()
{
	//Use SetFromUser() to enter data and make count
	block::count = block::SetFromUser();

	//Create a pointer to the block
	block *obj = new block[block::count];

	//Pouring information from data_forSet_obj to block
	//data_forSet = a struct for keep user data
	for (int i = 0; i < block::count; i++)
	{
		obj[i].set(&data_forSet_obj[i]);
	}

	//use PrintData(block object,int count) to display the block
	block::PrintData(obj, block::count);

	getchar();
	return 0x0;
}
