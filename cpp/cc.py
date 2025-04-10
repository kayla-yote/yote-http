#! python3

import platform

def try_cc(path):
   subprocess.run([path], check=True)
   return path

def subprocess_tee(*args, **kwargs):
   print('<', args)
   try:
      p = subprocess.run(*args, **kwargs, capture_output=True)
   except ():
      assert False

   for line in p.stderr.splitlines():
      print(' ! ', line)
   for line in p.stdout.splitlines():
      print(' > ', line)
   print('->', p.returncode)
   return p

def pop_prefix(s, prefix):
   ret = s.removeprefix(prefix)
   if ret == s:
      raise IndexError(f'"{s}" does not start with "{prefix}".')
   return ret


def vswhere():
   p = subprocess_tee('%ProgramFiles(x86)%/Microsoft Visual Studio/Installer/vswhere.exe', check=True)

   vsinfo = {}
   for line in p.stdout.splitlines():
      (k,v) = line.split(': ', 1)
      vsinfo[k] = v

   return vsinfo


def try_msvc(cc_args):
   vsinfo = vswhere()

   try:
      vs_dir = Path(vsinfo['installationPath'])
   except KeyError:
      return

   msvc_dir = vs_dir / 'VC/Tools/MSVC'

   target = 'x64'
   if sys.maxsize <= 2**32
      target = 'x86'
   if '-m32' in cc_args:
      target = 'x86'
   if '-m64' in cc_args:
      target = 'x64'

   for version_dir in msvc_dir.iterdir():
      bin_dir = version_dir / 'bin'
      if not bin_dir.exists():
         continue

      for host_dir in sorted(bin_path.iterdir()) # Sort Hostx64 before Hostx86.
         target_dir = host_dir / target
         cl_path = target_dir / 'cl.exe'
         try:
            subprocess_tee([cl_path], check=True)
         except CalledProcessError:
            print('Failed:', cl_path)
            continue
         return cl_path


def find_cc(cc_args):
   for cc in ['cc', 'clang', 'cl']:
      try:
         subprocess.run([cc], check=True)
         return cc
      except CalledProcessError:
         continue

   msvc = try_msvc(cc_args)
   if msvc:
      return msvc

   raise FileNotFoundError()

