#!/usr/bin/env python3
import sys

from cli import lparser, lundump


def main() -> None:
  if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <xdi_file>", file=sys.stderr)
    sys.exit(1)

  lc = lundump.LuaUndump()
  print(sys.argv[1])
  chunk = lc.loadFile(sys.argv[1])
  print("[*] format: XDI")

  lc.print_dissassembly()

  lp = lparser.LuaDecomp(chunk)

  print("\n==== [[" + str(chunk.name) + "'s pseudo-code]] ====\n")
  print(lp.getPseudoCode())


if __name__ == "__main__":
  main()
