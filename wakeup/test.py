import sys
import re

def spl(ss):
    sss=re.split(r"\w[\W]\w",ss)
    print(sss)
    a=len(sss)
    #if a>1:
      #  for i in a:
       #     spl(s[a])
            
    return a

def countwords(s):
     count=len(s.split())
     return count

s=" world!I'"
print(spl(s))
