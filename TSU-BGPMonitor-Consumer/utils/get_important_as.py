import csv
import os
def get_important_as():
    important_as = []
    with open(os.path.abspath('static/2023-05_categorized_ases.csv'),'r') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) < 1:
                continue
            str_row = '|'.join(row)
            if 'Cloud' in str_row or 'cloud' in str_row or 'CLOUD' in str_row:
                important_as.append(str(row[0][2:]))
        
        return important_as


if __name__ == '__main__':
    print(len(get_important_as()))