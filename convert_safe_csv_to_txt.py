import csv

with open('safe_urls.csv', 'r', encoding='utf-8') as csv_file, open('safe_links.txt', 'w', encoding='utf-8') as txt_file:
    reader = csv.reader(csv_file)
    for row in reader:
        if row:  # skip empty lines
            txt_file.write(row[0].strip() + '\n')
