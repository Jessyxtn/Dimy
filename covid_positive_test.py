
import select
import sys


no_covid = True
active = True

while active and no_covid:
    print("Enter 'covid' to report COVID-19 positive (upload CBF):")
    
    # use select to implement a timeout for user input
    read, _, _ = select.select([sys.stdin], [], [], 3)
    if read:
        user_input = sys.stdin.readline().strip()
        if user_input.lower() == "covid":
            print(f"User reported covid positive.")
            no_covid = False