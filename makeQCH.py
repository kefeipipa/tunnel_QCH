#!/usr/bin/env python


def makeQCH(num):
    rline = range(num)
    sline = range(num)
    sline.reverse()
    RQline = []
    SQline = []
    for i in range(num):
	RQline += rline
        SQline += sline
        sline = sline[1:] + [sline[0]]
    return (RQline, SQline)




 

(a,b) =  makeQCH(4)
print a
print b
