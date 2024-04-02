import hashlib


def md5(s):
    return hashlib.md5(s).hexdigest()


questions = [
    'Q1: How many packets are captured as well as displayed in this pcap file?',
    'Q2: How long did it take to capture this pcap file?\n Format: XX min XX sec \n Hint: Do a difference of the time for last packet captured to the first packet captured.',
    'Q3: What is the Host IP address that has many packets, mostly communicating on the network?',
]


answer_hashes = [
    '0baa10f95ef302bf877f1f11e8ffef58',
    'e31b7167aa9b171bfb76abb8c9032011',
    '0778d4aaedef1d66984065b4649dd304'
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