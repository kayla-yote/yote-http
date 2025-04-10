#! python3

import base64
import concurrent.futures
import hashlib
import itertools
import os
from pathlib import *
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


# -
# HTTP/1.0 spec: https://datatracker.ietf.org/doc/html/rfc1945
# HTTP/1.1 spec: https://datatracker.ietf.org/doc/html/rfc2068

# -

ADDRESS = ('', 80)
ENABLE_HTCPCP = True
SERVER_HEADER_STR = 'yote_http/1.1'

# -

class RequestRange(NamedTuple):
   start: int
   end: int

   def size(self):
      return self.end - self.start

   def last(self):
      return self.end - 1



def parse_request_range(start_last, byte_size) -> RequestRange:
   (start,last) = start_last.split('-')
   start = start.strip()
   last = last.strip()

   if start == '':
      if last == '':
         return RequestRange(0, byte_size)

      return RequestRange(byte_size-int(last), byte_size)

   if last == '':
      return RequestRange(int(start), byte_size)

   return RequestRange(int(start), int(last)+1)

# -

class DigestInfo:
   path: Path
   mtime_ns: int = 0
   digest_by_alg: dict[str,str]


DIGEST_INFO_BY_PATH: dict[Path,DigestInfo] = {}


DIGESTERS_BY_ALG = {
   'sha': hashlib.sha1,
   'sha-256': hashlib.sha256,
   'sha-512': hashlib.sha512,
}

def repr_digest_file(path: Path, alg: str) -> str:
   digester = DIGESTERS_BY_ALG[alg]()

   data = path.read_bytes()
   digester.update(data)
   b = digester.digest()

   b64_str = base64.b64encode(b).decode()
   # Repr-Digest: sha-256=:AEGPTgUMw5e96wxZuDtpfm23RBU3nFwtgY5fw4NYORo=:
   return f'{alg}=:{b64_str}:'


def cached_repr_digest_file(path: Path, alg: str, stats: os.stat_result) -> str:
   try:
      di = DIGEST_INFO_BY_PATH[path]
   except KeyError:
      di = DigestInfo()
      di.path = path

   if stats.st_mtime_ns != di.mtime_ns:
      di.mtime_ns = stats.st_mtime_ns
      di.digest_by_alg = {}

   if alg not in di.digest_by_alg:
      di.digest_by_alg[alg] = repr_digest_file(path, alg)

   DIGEST_INFO_BY_PATH[path] = di
   return di.digest_by_alg[alg]


def parse_cskev(s: str):
   # e.g. s='sha-512=8, sha-256=6, adler=0, sha=1'
   for kev in [x.strip() for x in s.split(',')]:
      k_v = [x.strip() for x in kev.split('=', 1)]
      try:
         (k, v) = k_v
      except ValueError:
         (k, v) = k_v + ['']
      yield


def GET(req: RequestHeader) -> Optional[Response]:
   subpath = pop_prefix(req.uri.path, '/')
   path = G.SERVE_ROOT / subpath

   hardpath = path.resolve()

   for jail in G.GET_JAILS:
      hardjail = jail.resolve()
      try:
          hardpath.relative_to(hardjail)
          break
      except ValueError:
         continue
   else:
      return Response(403, 'Will neither confirm nor deny that path exists.')

   if path.is_dir():
      path = path / 'index.html'

   try:
      f = path.open('rb')
   except FileNotFoundError:
      return Response(404, 'yeah nah')

   with f:
      stats = path.stat()
      mtime = stats.st_mtime
      mtime_ns = stats.st_mtime_ns

      f.seek(0, os.SEEK_END)
      byte_size = f.tell()
      f.seek(0, os.SEEK_SET)

      content_type = content_type_from_path(path)

      res = Response(200, 'kay~')
      get_range_header = None
      is_range_get = req.method == 'GET' and 'Range' in req.headers
      if is_range_get:
         get_range_header = req.headers['Range']
         get_range_header = only_without_prefix(get_range_header, 'bytes=')
      if get_range_header:
         res = Response(206, 'k~')

      ranges_str = get_range_header or '0-'
      ranges = [parse_request_range(s.strip(), byte_size) for s in ranges_str.split(',')]

      def coalesce_ranges(ranges: list[RequestRange]) -> list[RequestRange]:
         ranges = sorted(ranges, key=lambda x: x.start)
         ret = [ ranges[0] ]
         for r in ranges[1:]:
            prev = ret[-1]
            if r.start <= prev.end:
               ret[-1] = RequestRange(prev.start, max(prev.end, r.end))
            else:
               ret += [r]
         return ret

      ranges = coalesce_ranges(ranges)

      # -

      def content_range_string(rr: RequestRange):
         return f'bytes {rr.start}-{rr.last()}/{byte_size}'
      def content_range_length(start, count):
         return count


      def send_range_body(rr: RequestRange):
         req.cs.send_file(f, rr.start, rr.size())

      def http_time(t: float):
         #  rfc1123-date = wkday "," SP date1 SP time SP "GMT"
         #  wkday        = "Mon" | "Tue" | "Wed"
         #               | "Thu" | "Fri" | "Sat" | "Sun"
         #  date1        = 2DIGIT SP month SP 4DIGIT
         #                 ; day month year (e.g., 02 Jun 1982)
         #  time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
         #                 ; 00:00:00 - 23:59:59
         st = time.gmtime(t)
         wkday = 'Mon Tue Wed Thu Fri Sat Sun'.split(' ')[st.tm_wday]
         month = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')[st.tm_mon-1]
         date1f = f'%d {month} %Y'
         timef = f'%H:%M:%S'
         return time.strftime(f'{wkday}, {date1f} {timef} GMT', st)

      res.headers['Date'] = http_time(time.time())
      res.headers['Last-modified'] = http_time(mtime)

      # -

      if wrd := req.headers.get('Want-Repr-Digest'):
         k_v_list = [kev.strip().split('=', 1) for kev in wrd.split(',')]
         k_v_list = sorted(k_v_list, key=lambda x: -int(x[1])) # Highest preference first
         for (alg, preference_str) in k_v_list:
            preference_val = int(preference_str)
            if preference_val <= 0:
               continue
            if alg not in DIGESTERS_BY_ALG:
               print(f'Warning: Want-Repr-Digest alg "{alg}" not recognized.')
               continue
            rd = cached_repr_digest_file(path, alg, stats)
            res.headers['Repr-Digest'] = rd

      # -

      if len(ranges) == 1:
         # >Content-Range: bytes 21010-47021/47022
         # >Content-Length: 26012
         rr = ranges[0]
         res.headers['Content-type'] = content_type
         res.headers['Content-length'] = f'{rr.size()}'

         if get_range_header:
            res.headers['Content-range'] = content_range_string(rr)
         send_response_header(req.cs, res)
         if req.method == 'GET':
            send_range_body(rr)
         return None

      # multipart/byteranges:
      '''
      HTTP/1.1 206 Partial content
      Date: Wed, 15 Nov 1995 06:25:24 GMT
      Last-modified: Wed, 15 Nov 1995 04:58:08 GMT
      Content-type: multipart/byteranges; boundary=THIS_STRING_SEPARATES

      --THIS_STRING_SEPARATES
      Content-type: application/pdf
      Content-range: bytes 500-999/8000

      ...the first range...
      --THIS_STRING_SEPARATES
      Content-type: application/pdf
      Content-range: bytes 7000-7999/8000

      ...the second range
      --THIS_STRING_SEPARATES--
      '''
      boundary = uuid.uuid4() # Unguessable, won't collide with body.
      boundary_str = str(boundary)

      res.headers['Content-type'] = f'multipart/byteranges; boundary={boundary_str}'
      send_response_header(req.cs, res)

      part_headers = {}
      part_headers['Content-type'] = content_type
      for rr in ranges:
         part_headers['Content-range'] = content_range_string(rr)

         req.cs.send_line(f'--{boundary_str}')
         send_header_lines(req.cs, part_headers)
         send_range_body(rr)

      req.cs.send_line(f'--{boundary_str}--')
      return None

# -

import mod_htcpcp

def response_from_request(req: RequestHeader) -> Optional[Response]:
   if ENABLE_HTCPCP:
      if ret := mod_htcpcp.respond_htcpcp(req):
         return ret

   # -

   if req.method == 'POST':
      if 'Content-Length' not in req.headers:
         return Response(400, 'Missing Content-Length.')

      return Response(403, 'yeah nah')

   # -

   if req.method in ['GET', 'HEAD']:
      return GET(req)

   return Response(501, f'Unrecognized method: {req.method}')

# -

def send_response_header(cs: HttpSocket, res: Response):
   res.headers['Server'] = SERVER_HEADER_STR

   cs.send_line(f'{SERVER_HTTP_VERSION} {res.code} {res.reason_phrase}')
   for k,v in res.headers.items():
      cs.send_line(f'{k}: {v}')
   cs.send_line('')


def handle_client(s: socket.socket, addr: str):
   with s:
      try:
         cs = HttpSocket(s, addr)

         client_id = next(G.CLIENT_ID_COUNTER)
         T.log_prefix = f'[{client_id}]'

         while True:
            # Request-Line = Method SP Request-URI SP HTTP-Version CRLF
            request_line = cs.recv_line()
            if request_line == None:
               break
            log(1, request_line)
            (method, uri_str, http_version_str) = request_line.split(' ')
            uri = urllib.parse.urlsplit(uri_str)
            http_version_str = pop_prefix(http_version_str, 'HTTP/')
            http_version = [int(x) for x in http_version_str.split('.')]

            headers: dict[str,str] = {}
            while line := cs.recv_line():
               (k,v) = line.split(':', 1)
               headers[k.strip()] = v.strip()

            req = RequestHeader(cs, method, uri, http_version, headers)

            if req.http_version >= [1,1]:
               AIZUCHI = [
                  'はい',
                  'ええ',
                  'うん',
                  'そう',
                  'そうですか',
                  'そっか',
                  'へえ',
                  '本当に',
               ]
               continue_res = Response(100, random.choice(AIZUCHI)+'~')
               send_response_header(cs, continue_res)

            res = response_from_request(req)

            if res:
               send_response_header(cs, res)

            continue
      except ConnectionAbortedError:
         log(2, 'ConnectionAbortedError')
         pass
      except ExHttpSocketDisconnected:
         log(1, 'Client disconnected.')
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

            cs.send_line(f'HTTP/1.0 500 ><')
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

   G.GET_JAILS = [G.SERVE_ROOT]

   # -

   def thread__accept() -> None:
      s_list: list[socket.socket] = []
      def create_server(*args, **kwargs):
         try:
            s = socket.create_server(*args, **kwargs)
            print(*args)
            s_list.append(s)
         except:
            traceback.print_exc()
      create_server(ADDRESS, family=socket.AF_INET)
      create_server(ADDRESS, family=socket.AF_INET6)

      while True:
         (ready,_,_) = select.select(s_list,[],[])
         for s in ready:
            (client_s, client_addr) = args = s.accept()

            threading.Thread(target=handle_client, args=(client_s, client_addr), name='handle_client', daemon=True).start()

   threading.Thread(target=thread__accept, name='thread__accept', daemon=True).start()

   while True:
      time.sleep(10)
