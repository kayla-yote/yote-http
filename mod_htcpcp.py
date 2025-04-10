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

from utils import *

# -------------------------------------
# Nonsense.

IMPLY_HTCPCP_FROM_CONTENT_TYPE = True
IMPLY_HTCPCP_FROM_METHOD_BREW = True

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
   'k\xC3\xA1va', # Czech  <- My errata! -Kayla
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
def is_scheme_htcpcp(scheme: str) -> bool:
   assert not scheme.endswith(':'), scheme
   if scheme.lower() not in HTCPCP_SCHEMES:
      return False

   GERMAN_SCHEME = '%4Baffee'
   if scheme.lower() == GERMAN_SCHEME.lower() and scheme[0] != GERMAN_SCHEME[0]:
      # > Note that while URL scheme names are case-independent, capitalization is
      # > important for German and thus the initial "K" must be encoded.
      return False

   return True



HTCPCP_CONTENT_TYPES_COFFEE = set(['message/coffeepot', 'application/coffee-pot-command'])
HTCPCP_CONTENT_TYPES_TEA = set(['message/teapot'])
HTCPCP_CONTENT_TYPES = HTCPCP_CONTENT_TYPES_COFFEE | HTCPCP_CONTENT_TYPES_TEA

def is_request_htcpcp(req: RequestHeader) -> bool:
   scheme = req.uri.scheme
   if scheme:
      return is_scheme_htcpcp(scheme)

   if IMPLY_HTCPCP_FROM_METHOD_BREW:
      if req.method == 'BREW':
         return True
   if IMPLY_HTCPCP_FROM_CONTENT_TYPE:
      ct = req.headers.get('Content-Type')
      if ct in HTCPCP_CONTENT_TYPES:
         return True

   return False


CONTENT_TYPE_BY_POT_PATH: dict[str,str] = {
   #'/': 'message/coffeepot',
   #'/tea': 'message/teapot',
   '/kofi': 'message/coffeepot',
}

def respond_htcpcp(req: RequestHeader) -> Optional[Response]:
   # HTCPCP: https://datatracker.ietf.org/doc/html/rfc2324
   # HTCPCP-TEA: https://datatracker.ietf.org/doc/html/rfc7168

   if not is_request_htcpcp(req):
      return None

   if req.method in ['BREW','POST']:
      header_ct = req.headers.get('Content-Type')
      if header_ct and header_ct not in HTCPCP_CONTENT_TYPES:
         return Response(501, f'Unrecognized Content-Type "{header_ct}" not in {HTCPCP_CONTENT_TYPES}.')

      pot_ct = CONTENT_TYPE_BY_POT_PATH.get(req.uri.path, None)
      if header_ct != pot_ct:
         if header_ct != 'message/teapot':
            return Response(418, "I'm a teapot")
         else:
            return Response(418, "I'm NOT a teapot")

      return Response(402, f'https://ko-fi.com/kaylayote')


   if req.method == 'GET':
      return Response(204, f'No caffeine may be retrieved electronically.')

   if req.method == 'WHEN':
      return Response(409, f'Server is not currently pouring milk.')

   return Response(501, f'Unrecognized method: {req.method}')
