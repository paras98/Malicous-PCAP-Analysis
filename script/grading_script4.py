import hashlib


def md5(s):
    return hashlib.md5(s).hexdigest()


questions = [
    'Q1: What is the threat category of both the executable files?',
    'Q2: How many days have passed since the malware(imgpaper.png) was first detected? Answer is in months.',
    'Q3: How many days have passed since the malware(cursor.png) was first detected? Answer is in days.',
    'Q4: Based on the report provided at this time, how many security vendors flagged these files as malicious. Format: 10/20,23/30'
]


answer_hashes = [
    '2806906c79cdb8ef05d9595ff8cdc125',
    'eccbc87e4b5ce2fe28308fd9f2a7baf3',
    '3c59dc048e8850243be8079a5c74d079',
    '8468223e36014b3116651a20d299d60b'
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