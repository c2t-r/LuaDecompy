#!/usr/bin/env python3
import argparse

from cli import lparser, lundump


def _build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(prog="xdilua")
  parser.add_argument("input_file", help="path to XDI bytecode")
  parser.add_argument(
    "-p",
    "--pesudo",
    dest="pseudo",
    action="store_true",
    help="print pseudocode instead of disassembly blocks",
  )
  return parser


def main() -> None:
  parser = _build_parser()
  args = parser.parse_args()

  lc = lundump.LuaUndump()
  chunk = lc.loadFile(args.input_file)

  if args.pseudo:
    lp = lparser.LuaDecomp(chunk)
    print(lp.getPseudoCode())
  else:
    lc.print_dissassembly()


if __name__ == "__main__":
  main()
