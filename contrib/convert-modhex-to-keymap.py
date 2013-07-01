#!/usr/bin/python

import optparse
import sys

KEYMAPS = {"default":"cbdefghijklnrtuv",
           "modhex":"default",
           "dvorak":"jxe.uidchtnbpygk",
           "colemak":"cbsftdhuneikpglv"}

def lookup_keymap(keymap):
  while keymap in KEYMAPS:
    keymap = KEYMAPS[keymap]
  assert len(keymap) == len(set(keymap)) == 16, "Invalid keymap."
  return keymap

def main():
  parser = optparse.OptionParser()
  parser.add_option("-d", help="Use this as destination keymap instead of default modhex.",
                    default="default")
  parser.set_usage("%s [-d dest_kemap] src_keymap OTP\n\t(keymaps may be a literal keymapping such as %s or a nickname such as dvorak)\n\tKnown nicknames: %s" % (sys.argv[0], KEYMAPS["default"], ', '.join(KEYMAPS)))
  opts, argv = parser.parse_args()

  if len(argv) != 2:
    parser.print_usage()
    return

  src, opt = argv

  lut = dict(zip(*map(lookup_keymap, (src, opts.d))))
  print ''.join(map(lut.get, opt))

if __name__ == "__main__":
  main()
