import hashlib


def md5(s):
    return hashlib.md5(s).hexdigest()


questions = [
    'Q1: What is the IP address of the infected machine?',
    'Q2: What is its HOST name? (Answer is in ALL CAPS)',
    'Q3: What is the user account name for the infected Windows client? Format: (XXX-XXXX-X#-XX)',
    'Q4: What is the other user account name in the Trickbot HTTP POST traffic? Note: Answer in following syntax ',
    'Q5: What is the infected user\'s email password?'
]

answer_hashes = [
    '0778d4aaedef1d66984065b4649dd304',
    'bfea86b1ed5733b500b26248eaed7d2b',
    '681331d989498a54b75c220c290d1165',
    '3cb21a7f9108abe8eeee3ef64834eb5a',
    'b81a2f06310645f2f200ab1bf5a8fa95'
]
print("Based on the Trickbot infection's HTTP POST traffic")


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