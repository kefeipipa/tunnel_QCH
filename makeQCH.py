#!/usr/bin/env python


def makeQCH(num):
    line = range(num)
    sline = line
    RQline = []
    SQline = []
    for i in range(num):
	RQline += line
        SQline += sline
        sline = sline[1:] + [sline[0]]
    return (RQline, SQline)




 

#makeQCH(4)
