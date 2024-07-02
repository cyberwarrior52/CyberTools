```
    _    ____  ____    ____  ____   ___   ___  _____ 
   / \  |  _ \|  _ \  / ___||  _ \ / _ \ / _ \|  ___|
  / _ \ | |_) | |_) | \___ \| |_) | | | | | | | |_   
 / ___ \|  _ <|  __/   ___) |  __/| |_| | |_| |  _|  
/_/   \_\_| \_\_|     |____/|_|    \___/ \___/|_|    
                                                     
 ____  _____ _____ _____ ____ _____ ___  ____   
|  _ \| ____|_   _| ____/ ___|_   _/ _ \|  _ \  
| | | |  _|   | | |  _|| |     | || | | | |_) | 
| |_| | |___  | | | |__| |___  | || |_| |  _ <  
|____/|_____| |_| |_____\____| |_| \___/|_| \_\ 
                                                                  
```

# Purpose of this tool? 
This tool is used to find and prevent from arp spoofing attack

# Dependencies
```
sudo apt update
sudo apt upgrade
sudo apt install libpcap-dev
```
# If we won't install above dependencies, this tool won't work

# Step by step guid to demonstrate it,

Firstly,We clone our git repo
```
git clone https://git.selfmade.ninja/mohamedhathim628/linux-with-c.git

```
Secondly,We enter this directory
```
cd ARPspoofdetector

```
Thirdly,
```
ls

```

Fourthly,compile the C file
```
gcc arpspoofdetector.c -o arpspoofdetect -lpcap

```

Finally,We run the file
```
sudo ./arpspoofdetect [flags]

```