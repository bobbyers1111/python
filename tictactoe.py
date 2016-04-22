#!/usr/bin/python

import re
import sys
from random import random

#   +-----------------+
#---| class TicTacToe |--------------------------------------------------------
#   +-----------------+

class TicTacToe():

  def __init__(self,rows=3,cols=3):
    self.move = 0
    self.rows = rows
    self.cols = cols
    self.UImode = 'CONSOLE'
    self.board = [ [' ' for col in range(cols)] for row in range(rows) ]

  #-------------------------------------
  def print(self):

    if self.UImode == 'CONSOLE':

      print()
      print('     ', end='')
      print('+---'*self.cols+'+')

      for row in self.board:

        print('     |', end='')
        for elem in row:
          print(' %1c |' % elem, end='')
        print()

        print('     ', end='')
        print('+---'*self.cols+'+')

  #-------------------------------------
  def haverow(self,row,player):
      '''
      Determine if a player 'has' (owns) a row
      Returns True if the player has it. False otherwise.
      '''

      haveIt = True

      for square in self.board[row]:
        if self.board[square] != player:
          haveIt = False
          break

      return haveIt

  #-------------------------------------
  def takeSquare(self,square,player):
      '''
      Attempt to grant ownership of a square to a player. Returns
      True if (and only if) the square is successfully granted to
      the player. Returns False in all other cases.
      '''

      for row in self.board:
        print('row:',row)
  
      print('self.board[1][1]:', self.board[1][1])
  
      try:
        if self.board[square] != ' ':
          print('        ',square,'already taken')
          return True
        else:
          print()
          print('======================')
          print('     player',player,'takes',square)
          self.board[square] = player
          self.move += 1
          return False
      except:
        print('an exception occurred while player',player,'attemptded to take square', square)
        return True

  #-------------------------------------
  def iswinner(self,player):

    for row in self.board:
      if self.haverow(row,player):
        print()
        print('ATTENTION: Player',player,'owns all of row',row)
        return True

    return False

  #-------------------------------------
  def doPlayerTurn(self,player):

    if self.UImode == 'CONSOLE': 

      x, y = map(int, re.split('[, ]',input('Player %c, enter your move (row,column): ')))

      while ticTacToe.takeSquare(square,player):
        print()
        print('     Please enter a row and column in the form \'r,c\'')
        square = input('           try again: ')

      self.print()

#(end of class TicTacToe)
#-----------------------------------------------------------------------

#   +------+
#---| MAIN |------------------------------------------------------------
#   +------+

playerX = 'X'
playerO = 'O'
ticTacToe = TicTacToe()
ticTacToe.print()

while True:

  for player in (playerX, playerO):

    print()
    print('Player',player,', it is your turn..')

    ticTacToe.doPlayerTurn(player)

    if ticTacToe.iswinner(player):
      print()
      print('      PLAYER',player,'IS THE WINNER !!!')
      print()
      sys.exit(ord(player))

