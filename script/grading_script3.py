import hashlib


def md5(s):
    return hashlib.md5(s).hexdigest()


questions = [
    'Q1: What is the name of the first executable file that  is sent in the network traffic?',
    'Q2: What is the name of the second executable file that is sent in the network traffic?',
    'Q3: What are the SHA256 file hashes for the first file?',
    'Q4: What are the SHA256 file hashes for the second file?'
]


answer_hashes = [
    '58ef9e5521f989227e95bc7072844ec7',
    '9f038b97a794800830ad261b61269681',
    '067eda24cc256ad3d45418649fe7167a',
    '7903e88ac5690ba72dce9cdad17b50fd'
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