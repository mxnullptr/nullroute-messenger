#!/usr/bin/env python3
import os
import subprocess
import sys


SEASTAR_COMMIT = '26badcb14c1b8a03547d5b7fb24ab6b5f4c42299'


def run_commands(_error_label, _commands):
  for command in _commands:
    print(f'>>> {command}')
    result = subprocess.call(command, shell=True)
    if result != 0:
      print(f'[error] failed to build {_error_label}')
      sys.exit(-1)

# -------------------------------------------------------------------------------------------------------------------- #

def apply_arm_graviton_cpu_patch():
  patch = '''
@@ -97,6 +97,16 @@
             ['RTE_MAX_LCORE', 128],
             ['RTE_MAX_NUMA_NODES', 2]
         ]
+    },
+    '0xd4f': {
+        'march_features': ['sve2'],
+        'compiler_options': ['-mcpu=neoverse-v2'],
+        'flags': [
+            ['RTE_MACHINE', '"neoverse-v2"'],
+            ['RTE_ARM_FEATURE_ATOMICS', true],
+            ['RTE_MAX_LCORE', 144],
+            ['RTE_MAX_NUMA_NODES', 2]
+        ]
     }
 }
 implementer_arm = {
'''

  with open('arm_graviton_cpu.patch', 'wt') as filehandler:
    filehandler.write(patch)

  commands = [
    'patch dpdk/config/arm/meson.build < arm_graviton_cpu.patch',
  ]
  run_commands('[seastar] dpdk arm cpu graviton patch', commands)

# -------------------------------------------------------------------------------------------------------------------- #

def disable_drivers_patch():
  """Remove GVE and IONIC drivers using sed"""

  meson_build_path = 'dpdk/drivers/net/meson.build'

  if not os.path.exists(meson_build_path):
    print(f'[warning] {meson_build_path} not found')
    return

  commands = [
    f"sed -i \"/'gve',/d\" {meson_build_path}",
    f"sed -i \"/'ionic',/d\" {meson_build_path}",
  ]
  run_commands('[seastar] disable gve/ionic drivers', commands)

# -------------------------------------------------------------------------------------------------------------------- #

def build_seastar_framework():
  os.chdir('build')

  commands = [
    'git clone https://github.com/scylladb/seastar',
  ]
  run_commands('[seastar] prepare', commands)

  os.chdir('seastar')
  
  commands = [
    f'git checkout {SEASTAR_COMMIT}',
  ]
  run_commands('[seastar] checkout version', commands)

  if os.getegid() == 0:
    commands = [ './install-dependencies.sh' ]
    run_commands('[seastar] install dependencies', commands)

  commands = [
    'git submodule init',
    'git submodule update',
  ]
  run_commands('[seastar] build dpdk', commands)

  apply_arm_graviton_cpu_patch()
  disable_drivers_patch()

  commands = [
    './configure.py --mode=release --enable-dpdk --without-tests --without-apps --without-demos',
    'ninja -C build/release -j2'
  ]
  run_commands('[seastar] build', commands)

# -------------------------------------------------------------------------------------------------------------------- #

def main():
  commands = [
    './clean.py',
    'mkdir build'
  ]

  for command in commands:
    result = subprocess.call(command, shell=True)
    if result != 0:
      print('[error] unable prepare build')
      sys.exit(-1)

  build_seastar_framework()

# -------------------------------------------------------------------------------------------------------------------- #

if __name__ == '__main__':
  main()