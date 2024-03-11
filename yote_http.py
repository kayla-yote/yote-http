#! python3

import concurrent.futures
import itertools
import mmap
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


# -
# HTTP/1.0 spec: https://datatracker.ietf.org/doc/html/rfc1945
# HTTP/1.1 spec: https://datatracker.ietf.org/doc/html/rfc2068

# -

ADDRESS = ('', 80)
SERVER_PRODUCT_INFO = 'yote_http/1.0'

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

class ClientSocket:
   RECV_SIZE = 1024

   def __init__(self, conn: socket.socket, addr: str):
      self.conn = conn
      self.addr = addr
      self.recv_buffer = b''
      self.pos = 0


   def send_line(self, line: str):
      b = line.encode() + HTTP_EOL
      log(2, f'< {b!r}')
      self.conn.sendall(b)


   def send_bytes(self, mv: memoryview):
      log(2, f'< [{len(mv)} bytes]')
      self.conn.sendall(mv)


   def recv_split(self, delim: bytes) -> tuple[bytes,bytes]:
      pos = 0
      while True:
         # Ensure we catch e.g. '\r\n' if we recv '\r' and then '\n' split from eachother.
         pos = max(0, pos-len(delim)-1)
         try:
            delim_pos = self.recv_buffer.index(delim, pos)
         except ValueError:
            more = self.conn.recv(self.RECV_SIZE)
            if not more:
               delim_pos = len(self.recv_buffer)
               delim = b''
               break
            log(2, f'> {more!r}')
            self.recv_buffer += more
            continue
         break
      ret = self.recv_buffer[:delim_pos]
      self.recv_buffer = self.recv_buffer[len(ret)+len(delim):]
      return (ret, delim)


   def recv_line(self) -> str:
      (b,_) = self.recv_split(HTTP_EOL)
      s = b.decode()
      return s

# -

# https://www.iana.org/assignments/media-types/media-types.xhtml
MIME_TYPE_BY_SUFFIX: dict[str,str] = {
   '.css': 'text/css',
   '.csv': 'text/csv',
   '.html': 'text/html',
   '.js': 'text/javascript',
   '.md': 'text/markdown',
   '.txt': 'text/plain',
   '.wgsl': 'text/wgsl',
   '.xml': 'text/xml',
}
INFER_MIME_TYPES = True
if not INFER_MIME_TYPES:
   MIME_TYPE_BY_SUFFIX = {}


def content_type_from_path(path: pathlib.Path) -> Optional[str]:
   try:
      return MIME_TYPE_BY_SUFFIX[path.suffix]
   except KeyError:
      pass
   return None

# -

class BodyViewer:
   content_type: Optional[str] = None
   def __enter__(self):
      assert False
      return None

   def __exit__(self, *etc):
      assert False
      return

# -

class FileViewer(BodyViewer):
   path: pathlib.Path

   def __init__(self, path):
      self.content_type = content_type_from_path(path)
      self.path = path

   def __enter__(self):
      self.f = self.path.open('rb')
      self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
      return self.mm

   def __exit__(self, *etc):
      self.mm.close()
      self.mm = None
      self.f.close()
      self.f = None

# -

class MemoryViewer(BodyViewer):
   view: memoryview

   def __init__(self, view):
      self.view = view

   def __enter__(self):
      return self.view

   def __exit__(self, *etc):
      return

# -

class RequestHeader(NamedTuple):
   method: str
   uri: urllib.parse.SplitResult
   http_version: str
   headers: dict[str,str]


class Response(NamedTuple):
   code: int
   reason_phrase: str
   headers: dict[str,str]
   body: Optional[BodyViewer] = None

# -

class NoneManager:
   def __enter__(self):
      return None

   def __exit__(self, *etc):
      return

# -

def GET(req: RequestHeader) -> Response:
   subpath = req.uri.path
   assert subpath.startswith('/'), req.uri
   subpath = subpath.removeprefix('/')

   assert G.SERVE_ROOT
   path = G.SERVE_ROOT / subpath

   if path.is_dir():
      index = path / 'index.html'
      if index.exists():
         body = FileViewer(index)
         return Response(200, 'kay', {}, body)

   if path.is_file():
      body = FileViewer(path)
      return Response(200, 'kay', {}, body)

   return Response(404, 'yeah nah', {})

# -------------------------------------
# Nonsense.

HTCPCP_SCHEMES = set([x.lower() for x in [
   'koffie',      # Afrikaans, Dutch
   'q\xC3\xA6hv\xC3\xA6',              # Azerbaijani
   '\xD9\x82\xD9\x87\xD9\x88\xD8\xA9', # Arabic
   'akeita',      # Basque
   'koffee',      # Bengali
   'kahva',       # Bosnian
   'kafe',        # Bulgarian, Czech
   'caf\xC3\xE8', # Catalan, French, Galician
   '\xE5\x92\x96\xE5\x95\xA1',         # Chinese
   'kava',        # Croatian
   'k\xC3\xA1va', # Czech
   'kaffe',       # Danish, Norwegian, Swedish
   'coffee',      # English
   'kafo',        # Esperanto
   'kohv',        # Estonian
   'kahvi',       # Finnish
   '%4Baffee',    # German
   '\xCE\xBA\xCE\xB1\xCF\x86\xCE\xAD', # Greek
   '\xE0\xA4\x95\xE0\xA5\x8C\xE0\xA4\xAB\xE0\xA5\x80', # Hindi
   '\xE3\x82\xB3\xE3\x83\xBC\xE3\x83\x92\xE3\x83\xBC', # Japanese
   '\xEC\xBB\xA4\xED\x94\xBC',         # Korean
   '\xD0\xBA\xD0\xBE\xD1\x84\xD0\xB5', # Russian
   '\xE0\xB8\x81\xE0\xB8\xB2\xE0\xB9\x81\xE0\xB8\x9F', # Thai
]])

COFFEEPOTS: list[str] = [
   '/',
]
TEAPOTS: list[str] = [
#   '/pot-0/darjeeling',
#   '/pot-0/earl-grey',
#   '/pot-1/peppermint',
]

def htcpcp_request(req: RequestHeader) -> Optional[Response]:
   # HTCPCP: https://datatracker.ietf.org/doc/html/rfc2324
   # HTCPCP-TEA: https://datatracker.ietf.org/doc/html/rfc7168

   GERMAN_SCHEME = '%4Baffee'
   scheme = req.uri.scheme
   if scheme.lower() == GERMAN_SCHEME.lower() and scheme[0] != GERMAN_SCHEME[0]:
      # > Note that while URL scheme names are case-independent, capitalization is
      # > important for German and thus the initial "K" must be encoded.
      return None

   if req.method in ['BREW','POST']:
      ct = req.headers.get('Content-Type')
      if ct in ['message/coffeepot', 'application/coffee-pot-command']:
         if req.uri.path in COFFEEPOTS:
            return Response(402, f'https://ko-fi.com/kaylayote', {})
         if TEAPOTS:
            return Response(418, 'Tea only!', {})
         return Response(404, f'No coffeepot at requested URI.', {})

      if ct == 'message/teapot':
         if req.uri.path in TEAPOTS:
            return Response(402, f'https://ko-fi.com/kaylayote', {})
         return Response(404, f'No teapot at requested URI.', {})
      return Response(501, f'Unrecognized Content-Type: {ct}', {})

   if req.method == 'GET':
      return Response(204, f'No caffeine may be retrieved electronically.', {})

   if req.method == 'WHEN':
      return Response(409, f'Server is not currently pouring milk.', {})

   return Response(501, f'Unrecognized method: {req.method}', {})

# End nonsense.
# -------------------------------------

def response_from_request(req: RequestHeader) -> Response:
   if req.uri.scheme.lower() in HTCPCP_SCHEMES:
      if res := htcpcp_request(req):
         return res

   # -

   if req.method == 'POST':
      if 'Content-Length' not in req.headers:
         return Response(400, 'Missing Content-Length.', {})

      return Response(404, 'yeah nah', {})

   # -

   if req.method in ['GET', 'HEAD']:
      if res := GET(req):
         return res
      return Response(404, 'yeah nah', {})

   return Response(501, f'Unrecognized method: {req.method}', {})

# -

def handle_client(s: socket.socket, addr: str):
   with s:
      try:
         cs = ClientSocket(s, addr)

         client_id = next(G.CLIENT_ID_COUNTER)
         T.log_prefix = f'[{client_id}]'

         # Request-Line = Method SP Request-URI SP HTTP-Version CRLF
         request_line: str = cs.recv_line()
         log(1, request_line)
         (method, uri_str, http_version) = request_line.split(' ')
         uri = urllib.parse.urlsplit(uri_str)

         headers: dict[str,str] = {}
         while line := cs.recv_line():
            (k,v) = line.split(':', 1)
            headers[k.strip()] = v.strip()

         req = RequestHeader(method, uri, http_version, headers)
         res = response_from_request(req)

         with res.body or NoneManager() as data:
            res.headers['Server'] = SERVER_PRODUCT_INFO
            if data:
               assert res.body
               content_type = res.body.content_type
               if content_type:
                  res.headers['Content-Type'] = content_type
               res.headers['Content-Length'] = str(len(data))

            cs.send_line(f'HTTP/1.0 {res.code} {res.reason_phrase}')
            for k,v in res.headers.items():
               cs.send_line(f'{k}: {v}')
            cs.send_line('')

            if data and req.method != 'HEAD':
               cs.send_bytes(data)
         return
      except ConnectionAbortedError:
         log(2, 'ConnectionAbortedError')
         pass
      except:
         try:
            id = G.gen_internal_error_id()
            lines = [
               '-'*30,
               f'Request error {id}:',
               '',
               traceback.format_exc().strip(),
               '-'*30,
            ]
            log(0, '\n'.join(lines))

            cs.send_line(f'HTTP/1.0 500 uwu')
            cs.send_line('')
         except:
            traceback.print_exc()
      finally:
         s.shutdown(socket.SHUT_RDWR)
         pass


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

   (serve_root,) = args
   G.SERVE_ROOT = pathlib.Path(serve_root)
   assert G.SERVE_ROOT.is_dir(), G.SERVE_ROOT

   # -

   REQUEST_POOL = concurrent.futures.ThreadPoolExecutor(thread_name_prefix='client')

   def thread__accept() -> None:
      s_list: list[socket.socket] = []
      def create_server(*args, **kwargs):
         try:
            s = socket.create_server(*args, **kwargs)
            s_list.append(s)
         except:
            traceback.print_exc()
      create_server(ADDRESS, family=socket.AF_INET)
      create_server(ADDRESS, family=socket.AF_INET6)

      while True:
         (ready,_,_) = select.select(s_list,[],[])
         for s in ready:
            (client_s, client_addr) = s.accept()
            REQUEST_POOL.submit(handle_client, client_s, client_addr)

   threading.Thread(target=thread__accept, name='thread__accept', daemon=True).start()

   while True:
      time.sleep(10)
