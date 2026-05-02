#!/usr/bin/env python3
import subprocess
import sys


def main():
  commands = [
    './clean.py',
    'cmake .',
    'make -j2'
  ]

  for command in commands:
    result = subprocess.call(command, shell=True)
    if result != 0:
      print('[fatal] unable to build.')
      sys.exit(-1)
  sys.exit(0)


# -------------------------------------------------------------------------------------------------------------------- #

if __name__ == '__main__':
  main()