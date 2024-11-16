#include <iostream>
#include <string>
#include <stdlib.h>
#include <algorithm>
#include <cctype>
#include <pcap.h>

using namespace std;

string to_opposite_case(const string &input) {
    string result;
    for (char ch : input) {
        if (islower(ch)) {
            result += toupper(ch);
        } else if (isupper(ch)) {
            result += tolower(ch);
        } else {
            result += ch;
        }
    }
    return result;
}

void Interface(){
    system("clear");
    cout<<"                                                                                                                                                                                                                     "<<endl;
    cout<<"░▒▓█▓▒░░▒▓███████▓▒░        ░▒▓███████▓▒░░▒▓███████▓▒░  ░▒▓██████▓▒░  ░▒▓██████▓▒░ ░▒▓████████▓▒░      ░▒▓███████▓▒░ ░▒▓████████▓▒░░▒▓████████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░  "<<endl;
    cout<<"░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░          ░▒▓█▓▒░    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ "<<endl;
    cout<<"░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░          ░▒▓█▓▒░    ░▒▓█▓▒░      ░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ "<<endl;
    cout<<"░▒▓█▓▒░░▒▓███████▓▒░        ░▒▓██████▓▒░ ░▒▓███████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░     ░▒▓█▓▒░    ░▒▓██████▓▒░ ░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░  "<<endl;
    cout<<"░▒▓█▓▒░░▒▓█▓▒░                    ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░          ░▒▓█▓▒░    ░▒▓█▓▒░      ░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ "<<endl;
    cout<<"░▒▓█▓▒░░▒▓█▓▒░                    ░▒▓█▓▒░░▒▓█▓▒░       ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░          ░▒▓█▓▒░    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ "<<endl;
    cout<<"░▒▓█▓▒░░▒▓█▓▒░             ░▒▓███████▓▒░ ░▒▓█▓▒░        ░▒▓██████▓▒░  ░▒▓██████▓▒░ ░▒▓█▓▒░             ░▒▓███████▓▒░ ░▒▓████████▓▒░   ░▒▓█▓▒░    ░▒▓████████▓▒░░▒▓██████▓▒░   ░▒▓█▓▒░    ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ "<<endl;
    cout<<"                                                                                                                                                                                                                     "<<endl;
    cout<<"\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t-by Secure World                                                                                                                                                                                                                     "<<endl;                                                                                                                                                                                            
}

void print_help() {
    cout << "--------------------------------------\n";
    cout << "\tTHE AVAILABLE COMMANDS\n";
    cout << "--------------------------------------\n";
    cout << "help\t\t\t\t:\t\tFor print help." << endl;
    cout << "interfaces\t:\t\tFor listing all network devices from your device." << endl;
    cout << "start ghost :\t\tUsed to capture all packets over internet, and also find the packet IP is spoofed or not.\n" << endl;
}

void print_all_network_devices() {
    pcap_if_t *interfaces, *all_interface;
    char errbuf[PCAP_ERRBUF_SIZE];
    int get_devices = pcap_findalldevs(&all_interface, errbuf);

    if (get_devices == -1) {
        cout << "Can't list network interfaces due to: " << errbuf << endl;
    } else {
        cout << "--------------------------------------\n";
        cout << "\tTHE AVAILABLE INTERFACES\n";
        cout << "--------------------------------------\n";

        for (interfaces = all_interface; interfaces; interfaces = interfaces->next) {
            cout << "Device name: " << interfaces->name << endl;
        }
    }
    cout << '\n';
}

int main() {
    string user_cmd;
    Interface();
    while (true) {
        cout << "Enter Your Command: ";
        cin >> user_cmd;

        user_cmd = to_opposite_case(user_cmd);

        if (user_cmd == "help") {
            print_help();
        } else if (user_cmd == "interfaces") {
            print_all_network_devices();
        } else if (user_cmd == "start ghost") {
            cout << "Starting ghost functionality (to be implemented)...\n";
        } else {
            cout << "Error: No commands found for " << user_cmd << endl;
        }
    }
}

/*
Updated by Sibhi
*/
