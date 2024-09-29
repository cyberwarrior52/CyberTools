import time
from pywifi import const
import pywifi
import sys


# for printing help
def print_help(args):
    print("-i\tor\t--interfaces\t\t\t\t: To find your wireless network interface.\n")
    print("-s\tor\t--scan\t\t\t\t\t\t: To scan available wifi networks.\n")
    print("-c [wifi network name] or --connect : To connect wifi network you want.\n")
    print("Usage <command> :", args)


available_devices = []
final_password = []

# initialize pywifi
init_pyfi = pywifi.PyWiFi()

# To get the first interface of our device
interfaces = init_pyfi.interfaces()[0]

# Scan wireless WI-FI devices of our device and print it.
interfaces.scan()
all_network_device = interfaces.scan_results()

def connector(interface_ssid):
    if interfaces.status() == const.IFACE_CONNECTED:
        interfaces.disconnect()
        time.sleep(1)
        profile = pywifi.Profile()
        profile.ssid = interface_ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)

        pass_file = open("list.txt", "r")
        text_file = pass_file.read()

        for passw in text_file:
            profile.key = passw

            if profile.key == passw:
                final_password.append(passw)
                print(str(final_password))
                break
            else:
                pass


def main():
    if sys.argv[1] == "-i" or sys.argv[1] == "--interfaces":
        for all_devs in all_network_device:
            print("Network name :{}".format(all_devs.ssid))
            print("Network bssid :{}".format(all_devs.bssid))
            print("Network akm :{}".format(all_devs.akm))
            print("Network cipher :{}".format(all_devs.cipher))

    elif sys.argv[1] == "-s" or sys.argv[1] == "--scan":
        devices = interfaces.scan_results()
        for all_dev in devices:
            available_devices.append(all_dev.ssid)
            # remove_duplicate = duplicate_finder(available_devices)
        print(str(available_devices))
    elif sys.argv[1] == "-c" and sys.argv[2] or sys.argv[1] == "--connect" and sys.argv[2]:
        connector(sys.argv[2])
    elif sys.argv[1] == "-c" and not sys.argv[2] or sys.argv[1] == "--connect" and not sys.argv[2]:
        print_help(sys.argv[0])
        print("interface name not specified\n")
    else:
        print_help(sys.argv[0])
        print("Invalid command\n")

main()

