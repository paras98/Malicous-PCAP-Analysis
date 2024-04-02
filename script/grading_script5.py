import hashlib


def md5(s):
    return hashlib.md5(s).hexdigest()


questions = [
    'Q1: Victim Host IP address',
    'Q2: Victim Mac Address in format XX.XX.XX.XX.XX',
    'Q3: What is the victim Host Name. Note that it is case-sensitive',
    'Q4: What is the victim User Name',
    'Q5: How many file appeared in the files tab ( Hint follow the victim ip to identify )',
    'Q6: What are the real file name of the file masked as 1.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q7: What are the real file name of the file masked as 2.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q8: What are the real file name of the file masked as 3.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q9: What are the real file name of the file masked as 4.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q10: What are the real file name of the file masked as 5.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q11: What are the real file name of the file masked as 6.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q12: What are the real file name of the file masked as 7.jpg  ( Hint lookup in the images [Virustotal screenshot] ) ( Format to follow  name.dll )',
    'Q13: What is the name of the zip file ( Answer format name.zip)',
    'Q14: Based on the analysis what is the name of the Malware? '
]


answer_hashes = [
    'f161660a451f2bf0e10177a550f48297',
    'e6ef3c48223e3f4e1c2cfd1745a2b2fe',
    '2ae51eb796d421ab9bb7ffbd8cb8cc89',
    '6b50cb4f722243a559c58c068cd0b03c',
    '8f14e45fceea167a5a36dedd4bea2543',
    '5cad5792bb209694db6e36baa2ca83ea',
    '29c56a4b1fa4e5b6b57472fd9af6228a',
    '693bed4940fd3a2fe2a71a06dd643f34',
    '7e22e31bc672d6b7c69af89aebc96606',
    '4021392fb4666886bdbaf5664cad6a16',
    '02ee52e45c47362d986d95c57dc2fed0',
    '09354cfd31bc414f013d2848c949d2e2',
    '714e39189daf34738816a2f68e40899b',
    '726a688e70fa20fa37288f9a254eed59'
]


def prompt_question(question: str, expected_answer_hash: str):
    ans = input(question + '\n> ')
    if md5(ans.strip().replace(" ", "").encode()) != expected_answer_hash:
        print('Wrong answer, try again...')
        return prompt_question(question, expected_answer_hash)
    return 10


score = 0
total = len(questions) * 10
for i in range(len(questions)):
    score += prompt_question(questions[i], answer_hashes[i])
    print(f'Correct, your score is {score}')


print(f'Your final score is {score} / {total}!')