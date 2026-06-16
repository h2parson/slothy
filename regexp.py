import re

line = 'add eax, ebx'
regexp_text = '\\s*add\\s+([eE][abcdABCD][xX])\\s*,\\s*([eE][abcdABCD][xX])'

regexp = re.compile(regexp_text)

regexp_result = regexp.match(line)

print(regexp_result)