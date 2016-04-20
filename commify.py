#/usr/bin/python

"""
SCRIPT: commify.py
AUTHOR: bob byers
(c) 2016

Demos a function that takes a number (float or integer) as input and
returns it as a string with 1000s separators.

This is a very easy project. The only features of note are:

(1) Algorithm is based on first reversing the digits of the integer,
    copying each digit to an output buffer and adding a comma every
    third digit.

(2) Uses python's extended slice syntax in order to easily reverse a
    string. For example:

        reversed = original[::-1]

TO DO:

+ Support negative integers and floats.

+ Perform additional input validation.

+ Set the Euro option via an optional argument, a command-line arg, an
  environment variable or the system's LOCALE setting (or some
  combination of all).

"""

import re
import random as ra

#-- The maximum numbers to generate and process

MAXNUMS = 100

#-----------------------------------------------------------------------
#--- FUNCTION commify

def commify(input):

  """
    This function takes as input a non-negative integer and returns the
    integer as a string with 1000s delimiters applied.

    ARGS:
      input     A non-negative integer

    We optionally support European style 1000s delimiters (they use a
    decimal point instead of a comma), which is controlled by the 'Euro'
    variable

  """

  #-- Set the Euro style or not

  Euro = False
  if Euro:
    comma = '.'
  else:
    comma = ','

  #-- Begin processing by reversing all digits of the integer

  buf = str(input)[::-1]

  #-- 'i' is the characters processed, 'commified' is the result

  i = 0
  commified = ''

  #-- Loop through the reversed digits, one at a time

  for char in buf:

    #-- Of course every digit is included in the result

    commified += char

    #-- Every third digit gets followed by a comma, though
    #-- not the last digit (to avoid a leading comma)

    i += 1
    if i % 3 == 0 and i < len(buf):
      commified += comma

  #-- Un-reverse the digits

  commified = commified[::-1]

  #-- and return the result!

  return commified

#------------------------------------------------------------------------
#--- MAIN

print ('Here are', MAXNUMS, 'commified numbers..')

for i in range(MAXNUMS):
  randnum = ra.randint(0,0xFFFFFFFF)
  print ('    %10d = %15s' %  (randnum, commify(randnum)))

