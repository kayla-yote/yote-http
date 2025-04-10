#! python3

import concurrent.futures
import itertools
import pathlib
import random
import select
import socket
import sys
import threading
import time
import traceback
from typing import NamedTuple,Optional,Iterable,IO
import urllib.parse
import uuid

# -

SERVER_HTTP_VERSION = 'HTTP/1.1'

# -

def fuzzy_time(stddev_secs = 60.0) -> str:
   raw_time = time.time()
   r = random.normalvariate() * stddev_secs
   time_t = time.localtime(raw_time + r)
   s = time.strftime('%Y%b%d-%H:%M:%S', time_t)
   return s

# -

class Globals:
   CLIENT_ID_COUNTER = itertools.count(start=1)
   SERVE_ROOT: Optional[pathlib.Path]
   GET_JAILS: list[pathlib.Path]
   INTERNAL_ERROR_COUNTER = itertools.count(start=1)

   def gen_internal_error_id(self) -> str:
      num = next(self.INTERNAL_ERROR_COUNTER)
      ts = fuzzy_time()
      return f'#{num}/{ts}'


class ThreadLocal(threading.local):
   log_prefix = ''


G = Globals()
T = ThreadLocal()

# -


VERBOSE = 10
def log(v,*args):
   if VERBOSE < v:
      return
   if T.log_prefix:
      print(T.log_prefix, *args)
   else:
      print(*args)

# -

HTTP_EOL = b'\r\n'

class ExHttpSocketDisconnected(Exception):
   pass

class HttpSocket:
   RECV_SIZE = 1024

   def __init__(self, conn: socket.socket, addr: str):
      self.conn = conn
      self.addr = addr
      self.recv_buffer = b''
      self.pos = 0


   def send_line(self, line: str):
      log(2, f'< {line!r}')
      b = line.encode() + HTTP_EOL
      #log(2, f'< {b!r}')
      self.conn.sendall(b)


   def send_bytes(self, mv: memoryview):
      log(2, f'< [{len(mv)} bytes]')
      self.conn.sendall(mv)


   def send_file(self, f: IO[bytes], offset, size):
      log(2, f'< [{size} bytes from file offset {offset}]')

      if size:
         self.conn.sendfile(f, offset, size)


   def recv_split(self, delim: bytes) -> bytes:
      pos = 0
      while True:
         # Ensure we catch e.g. '\r\n' if we recv '\r' and then '\n' split from eachother.
         pos = max(0, pos-len(delim)-1)
         try:
            delim_pos = self.recv_buffer.index(delim, pos)
            break
         except ValueError:
            pass
         more = self.conn.recv(self.RECV_SIZE)
         if not more:
            raise ExHttpSocketDisconnected()
         log(2, f'> ({more!r})')
         self.recv_buffer += more
         continue

      ret = self.recv_buffer[:delim_pos]
      self.recv_buffer = self.recv_buffer[len(ret)+len(delim):]
      return ret


   def recv_line(self) -> str:
      b = self.recv_split(HTTP_EOL)
      s = b.decode()
      log(2, f'> {s!r}')
      return s

# -

# https://www.iana.org/assignments/media-types/media-types.xhtml
MIME_TYPE_BY_SUFFIX: dict[str,str] = {
   '.css': 'text/css',
   '.csv': 'text/csv',
   '.html': 'text/html',
   '.js': 'text/javascript',
   '.md': 'text/markdown',
   '.mpd': 'application/dash+xml',
   '.txt': 'text/plain',
   '.wgsl': 'text/wgsl',
   '.xml': 'text/xml',
}
INFER_MIME_TYPES = True
if not INFER_MIME_TYPES:
   MIME_TYPE_BY_SUFFIX = {}


def content_type_from_path(path: pathlib.Path) -> str:
   try:
      return MIME_TYPE_BY_SUFFIX[path.suffix]
   except KeyError:
      pass
   return 'application/octet-stream'

# -

class RequestHeader(NamedTuple):
   cs: HttpSocket
   method: str
   uri: urllib.parse.SplitResult
   http_version: list[int]
   headers: dict[str,str]


class Response(NamedTuple):
   code: int
   reason_phrase: str
   headers: dict[str,str] = {}


class ExResponse(Exception):
   res: Response

   def __init__(self, *args):
      self.res = Response(*args)
      super().__init__(f'{self.res.code} {self.res.reason_phrase}')


# -

class NoneManager:
   def __enter__(self):
      return None

   def __exit__(self, *etc):
      return


def pop_prefix(s, prefix):
   ret = s.removeprefix(prefix)
   if ret == s:
      raise IndexError(f'not "{s}".startswith("{prefix}")')
   return ret


def only_without_prefix(s, prefix):
   ret = s.removeprefix(prefix)
   if ret != s:
      raise None
   return ret

# -

def send_header_lines(cs: HttpSocket, headers: dict[str,str]):
   for k,v in headers.items():
      cs.send_line(f'{k}: {v}')

   cs.send_line('')
