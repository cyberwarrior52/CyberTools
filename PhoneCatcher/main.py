import phonenumbers
from phonenumbers import geocoder,carrier,timezone
from colorama import Fore,init,Style
from os import system
from sys import exit

BOLD = Style.BRIGHT
RESET = Style.RESET_ALL

init()

def check_for_mobile_number(number):
    if phonenumbers.number_type(number) == phonenumbers.PhoneNumberType.MOBILE:
        return "Mobile Number"
    else:
        return "Not mobile number"

def _help():
    for line in range(41):
        print(f"{BOLD}={RESET}",end='')
    print()
    print(f"{BOLD}Syntax of number{RESET} : {Fore.GREEN}{BOLD}number{RESET} {BOLD}<xxxxxyyyyy>{RESET}")
    print(f"{Fore.BLUE}Example : number +91xxxxxyyyyy{RESET}\n")
    print("{}If you want to exit, use command \'exit\'{}".format(Fore.RED),RESET)
    for line2 in range(41):
        print(f"{BOLD}={RESET}",end='')
    print()

def main():
    system("clear")
    number = input(f"{Fore.GREEN}Enter number : {RESET}")
    number_parser = phonenumbers.parse(number)
    getregion = phonenumbers.region_code_for_number(number_parser)
    get_country_code = phonenumbers.country_code_for_region(getregion)

    #Show info to the user
    print(f"{BOLD}Number Owned by : {carrier.name_for_number(number_parser,'en')}")
    print("Geo location : {}".format(geocoder.description_for_valid_number(number_parser,'en')))
    print(f"Country code : {phonenumbers.country_code_for_valid_region(getregion)}")
    print(f"Region : {phonenumbers.region_code_for_number(number_parser)}")
    print(f"Region code : {phonenumbers.region_code_for_country_code(get_country_code)}")
    print(f"Is valid : {phonenumbers.is_valid_number(number_parser)}")
    print(f"Is valid for region : {phonenumbers.is_valid_number_for_region(number_parser,getregion)}")
    print(f"Is mobile number : {check_for_mobile_number(number_parser)}")
    print("Number contains alphabet characters : {}".format(phonenumbers.is_alpha_number(number_parser)))
    print("Time zone for country : {}{}".format(timezone.time_zones_for_geographical_number(number_parser),RESET))

def interface():
    system("clear")
    print("{}{}1.Phone number info gathering".format(BOLD,Fore.GREEN))
    print("2.help{}".format(RESET))

    while True:
        user_input = int(input("Enter your choice to continue : "))

        try:
            if user_input == 1:
                main()
            elif user_input == 2:
                _help()
            else:
                system("clear")
                continue
        except KeyboardInterrupt:
            YorN = input("Do you want to continue : ")
            if YorN == "y":
                continue
            else:
                exit()


if __name__ == "__main__":
    interface()