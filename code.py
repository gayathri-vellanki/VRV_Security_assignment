import re
import csv

with open('sample.log', 'r') as f:
    ls = f.readlines()

#Count Requests per IP Address
#pattern to identify ipaddress
ipaddress_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
lst = []
#get ipaddress used for request
for line in ls:
    lst.append(ipaddress_pattern.search(line)[0])
ipaddress_list = []
#Geting unique ipaddress
for i in lst:
    if i not in ipaddress_list:
        ipaddress_list.append(i)
#finding the request count
ip_dict = {'IP Address': 'Request Count'}
for i in ipaddress_list:
    ip_count = 0
    for j in lst:
        if i == j:
            ip_count = ip_count + 1
    ip_dict[i] = ip_count
mykeys = list(ip_dict.keys())
mykeys.sort()
#printing the request count in descending order
sd = {i: ip_dict[i] for i in mykeys}
for key, value in reversed(sd.items()):
    print(f"{key:<15} {ip_dict[key]:<15}")

#Identify the Most Frequently Accessed Endpoint:
url_words, actions = [], []
for line in ls:
    pattern = re.search(r'"(.*?)"', line)  # finding the url or resource path pattern
    if pattern:
        url = pattern.group()
        lst = re.split(' ', url)
        # appending the methods
        actions.append(lst)
        for i in lst:
            if i not in url_words:
                url_words.append(i)
#getting the endpoints
words_list = [word for word in url_words if word.startswith('/')]
method = {}
for i in words_list:
    word_count = 0
    for j in actions:
        if i in j:
            word_count = word_count + 1
        method[i] = word_count
val = max(method, key=method.get)
print("\n")
#printing endpoint having highest frequently accessed
print("Most Frequently Accessed Endpoint:")
print(val, " (Accessed ", max(method.values()), " times)")

#Detect Suspicious Activity
lines = []
threshold = 4  # considering the default threshold as 4
for line in ls:
    lst = re.split(r'[-\s"]', line)
    lines.append(lst)
suspect_dict = {'IP Address': 'Failed Login Attempts'}
for i in ipaddress_list:
    suspect_count = 0
    for j in lines:
        if i in j:
            if '401' in j:
                suspect_count = suspect_count + 1
    #finding suspect count greater than threshold
    if suspect_count > threshold:
        suspect_dict[i] = suspect_count
print('\n')
print("Suspicious Activity Detected:")
for key in suspect_dict:
    print(f"{key:<15} {suspect_dict[key]:<15}")

#saving result into log_analysis_results.csv
with open('log_analysis_results.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    sd = {i: ip_dict[i] for i in mykeys}
    for key, value in reversed(sd.items()):
        writer.writerow([key, value])
    writer.writerow(['\n'])
    writer.writerow(['Endpoint', 'Access Count'])
    writer.writerow([val, max(method.values())])
    writer.writerow(['\n'])
    for key, value in suspect_dict.items():
        writer.writerow([key, value])
