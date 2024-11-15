#include <iostream>
#include <string>
#include <stdlib.h>
#include <algorithm>
#include <cctype>
#include <pcap.h>
using namespace std;

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

void print_help(){
    cout<<"--------------------------------------\n";
    cout<<"\tTHE AVAILABLE COMMANDS\n";
    cout<<"--------------------------------------\n";
    cout<<"help\t\t\t\t:\t\tFor print help."<<endl;
    cout<<"interfaces\t:\t\tFor listing all network devices from your device."<<endl;
    cout<<"start ghost :\t\tUsed to capture all packets over internet, and also find the packet ip is spoofed ip or not.\n"<<endl;
}

void print_all_network_devices(){
    pcap_if_t *interfaces,*all_interface;
    char *error;
    int get_devices = pcap_findalldevs(&all_interface,error);

    if(get_devices == -1){
        cout<<"Can\'t list network interface due to"<<error;
    } else {
        cout<<"--------------------------------------\n";
        cout<<"\tTHE AVAILABLE INTERFACES\n";
        cout<<"--------------------------------------\n";

        for(interfaces = all_interface;interfaces;interfaces=interfaces->next){
            cout<<"Device name :"<<interfaces->name<<endl;
        }
    }
    cout<<'\n';
}

int main(){
    string user_cmd;
    Interface();
    while(true){
        cout<<"Enter Your Command : ";
        cin>>user_cmd;

        if(user_cmd == "help"){
            print_help();
            continue;
        }
        else if(user_cmd == "interfaces"){
            print_all_network_devices();
            continue;
        }
        else if(user_cmd == "start ghost"){ 
            //will.
        }
        else {
            cout<<"Error:no commmands found by "<<user_cmd<<endl;
            continue;
        }
    }
}

/**
 * Sibi, below is your task,
 * 
 * TASK:
 * 1.Make the function that's get the string and return the string to opposite case like (lower to upper) or (upper to lower).
 * 2.If you make the function, we use the function for 'user_cmd' variable to make the user input into lower case.
 */