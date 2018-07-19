src = [
  'cmdline.c',
  'stress.c',
  'main.c',
]

inc = include_directories('.')


exe = executable(
  'delta', src,
  dependencies: [pthreads, etpan, sequoia],
  link_with: lib,
  install: true,
)
