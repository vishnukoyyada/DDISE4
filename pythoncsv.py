import csv

with open('users.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['email', 'password'])  # header
    for i in range(1, 1001):
        email = f'user{i}@example.com'
        password = f'password{i}'
        writer.writerow([email, password])
