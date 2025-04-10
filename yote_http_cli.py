#! python3

import concurrent.futures
import itertools
import os
import pathlib
import random
import select
import socket
import sys
import threading
import time
import traceback
from typing import NamedTuple,Optional,Iterable
import urllib.parse
import uuid

from utils import *


# ----------------

if __name__ == '__main__':
   args = sys.argv
   while args:
      arg = args.pop(0)
      if arg.startswith('-v'):
         expected = '-' + 'v'*(len(arg)-1)
         assert arg == expected, arg
         VERBOSE = len(arg)-1
         continue

      break

   # -

   (server_addr,) = args

   try:
      (host, port_str) = server_addr.rsplit(':', 1)
      port = int(port_str)
   except ValueError:
      (host, port) = (server_addr, 80)


   s = socket.create_connection((host, port))
   hs = HttpSocket(s, f'{host}:{port}')

   runtime_start = time.time()
   def runtime_ms():
      t = time.time() - runtime_start
      return int(t * 1000)

   def thread__recv():
      while True:
         try:
            response = hs.recv_line()
         except ExHttpSocketDisconnected:
            break
         #print(f'[{runtime_ms()}] > {response}')
      print(f'[{runtime_ms()}] <socket closed>')

      exit(0)

   threading.Thread(target=thread__recv, name='thread__recv', daemon=True).start()

   def thread__send():
      while True:
         line = input('<< ')
         # Normalize to \r\n:
         line = line.replace('\r\n', '\n')
         line = line.replace('\n', '\r\n')
         hs.send_line(line)
   threading.Thread(target=thread__send, name='thread__send', daemon=True).start()

   try:
      while True:
         time.sleep(3600)
   except KeyboardInterrupt:
      pass