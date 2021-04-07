#!/usr/bin/python3
import sys
#from time import time,ctime

#print('Today is', ctime(time()))
#print("Hello, Python From print.py!")

for line in sys.stdin:
    if 'Exit' == line.rstrip():
        break
    print("From jira:", line)

