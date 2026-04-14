"""
l(un)dump.py

A Lua5.1 cross-platform bytecode deserializer && serializer. This module pulls int and size_t sizes from the
chunk header, meaning it should be able to deserialize lua bytecode dumps from most platforms,
regardless of the host machine.

For details on the Lua5.1 bytecode format, I read [this PDF](https://archive.org/download/a-no-frills-intro-to-lua-5.1-vm-instructions/a-no-frills-intro-to-lua-5.1-vm-instructions_archive.torrent)
as well as read the lundump.c source file from the Lua5.1 source.
"""

import array
import struct
from enum import Enum, IntEnum, auto


class InstructionType(Enum):
  ABC = (auto(),)
  ABx = (auto(),)
  AsBx = auto()


class Opcodes(IntEnum):
  LOADNIL = 0
  MUL = 1
  SETTABLE = 2
  LE = 3
  CLOSE = 4
  NEWTABLE = 5
  LOADK = 6
  POW = 7
  GETTABLE = 8
  TEST = 9
  LT = 10
  EQ = 11
  MOVE = 12
  SETGLOBAL = 13
  GETUPVAL = 14
  LOADBOOL = 15
  DIV = 16
  RETURN = 17
  ADD = 18
  GETGLOBAL = 19
  CONCAT = 20
  CALL = 21
  TAILCALL = 22
  CLOSURE = 23
  FORLOOP = 24
  SETLIST = 25
  FORPREP = 26
  TFORLOOP = 27
  SETUPVAL = 28
  JMP = 29
  MOD = 30
  NOT = 31
  SELF = 32
  UNM = 33
  TESTSET = 34
  LEN = 35
  SUB = 36
  VARARG = 37


class ConstType(IntEnum):
  NIL = 0
  BOOL = 1
  NUMBER = 3
  STRING = 4


_RKBCInstr = [
  Opcodes.SETTABLE,
  Opcodes.ADD,
  Opcodes.SUB,
  Opcodes.MUL,
  Opcodes.DIV,
  Opcodes.MOD,
  Opcodes.POW,
  Opcodes.EQ,
  Opcodes.LT,
]
_RKCInstr = [Opcodes.GETTABLE, Opcodes.SELF]
_KBx = [Opcodes.LOADK, Opcodes.GETGLOBAL, Opcodes.SETGLOBAL]

_XDIMAGIC = b"\x01XDI"


# is an 'RK' value a K? (result is true for K, false for R)
def whichRK(rk: int) -> bool:
  return (rk & (1 << 8)) > 0


# read an RK as a K
def readRKasK(rk: int) -> int:
  return rk & ~(1 << 8)


class Instruction:
  opcode: int
  A: int
  B: int
  C: int
  raw: int

  def __init__(self, type: InstructionType, name: str) -> None:
    self.type = type
    self.name = name
    self.raw = 0

  # 'RK's are special in because can be a register or a konstant. a bitflag is read to determine which
  def __formatRK(self, rk: int) -> str:
    if whichRK(rk):
      return "K[" + str(readRKasK(rk)) + "]"
    else:
      return "R[" + str(rk) + "]"

  def toString(self) -> str:
    instr = f"{self.name:>10s}"
    regs = ""

    if self.type == InstructionType.ABC:
      # by default, treat them as registers
      A = f"{self.A}"
      B = f"{self.B}"
      C = f"{self.C}"

      # these opcodes have RKs for B & C
      if self.opcode in _RKBCInstr:
        A = f"R[{self.A}]"
        B = self.__formatRK(self.B)
        C = self.__formatRK(self.C)
      elif self.opcode in _RKCInstr:  # just for C
        A = f"R[{self.A}]"
        C = self.__formatRK(self.C)

      regs = f"{A:>6s} {B:>6s} {C:>6s}"
    elif self.type == InstructionType.ABx or self.type == InstructionType.AsBx:
      A = f"R[{self.A}]"
      B = f"{self.B}"

      if self.opcode in _KBx:
        B = f"K[{self.B}]"

      regs = f"{A:>6s} {B:>6s}"

    return f"{instr} : {regs}"

  def getAnnotation(self, chunk: "Chunk") -> str:
    if self.opcode == Opcodes.MOVE:
      return f"move R[{self.B}] into R[{self.A}]"
    elif self.opcode == Opcodes.LOADK:
      return f"load {chunk.getConstant(self.B).toCode()} into R[{self.A}]"
    elif self.opcode == Opcodes.GETGLOBAL:
      return f"move _G[{chunk.getConstant(self.B).toCode()}] into R[{self.A}]"
    elif self.opcode == Opcodes.ADD:
      return f"add {self.__formatRK(self.C)} to {self.__formatRK(self.B)}, place into R[{self.A}]"
    elif self.opcode == Opcodes.SUB:
      return f"sub {self.__formatRK(self.C)} from {self.__formatRK(self.B)}, place into R[{self.A}]"
    elif self.opcode == Opcodes.MUL:
      return f"mul {self.__formatRK(self.C)} to {self.__formatRK(self.B)}, place into R[{self.A}]"
    elif self.opcode == Opcodes.DIV:
      return f"div {self.__formatRK(self.C)} from {self.__formatRK(self.B)}, place into R[{self.A}]"
    elif self.opcode == Opcodes.CONCAT:
      count = self.C - self.B + 1
      return f"concat {count} values from R[{self.B}] to R[{self.C}], store into R[{self.A}]"
    else:
      return ""


class Constant:
  def __init__(self, type: ConstType, data: str | float | bool | None) -> None:
    self.type = type
    self.data = data

  def toString(self) -> str:
    return f"[{self.type.name}] {str(self.data)}"

  # format the constant so that it is parsable by lua
  def toCode(self) -> str:
    if self.type == ConstType.STRING:
      assert isinstance(self.data, str)
      return '"' + self.data + '"'
    elif self.type == ConstType.BOOL:
      if self.data:
        return "true"
      else:
        return "false"
    elif self.type == ConstType.NUMBER:
      return f"{self.data:g}"
    else:
      return "nil"


class Local:
  def __init__(self, name: str, start: int, end: int) -> None:
    self.name = name
    self.start = start
    self.end = end


class Chunk:
  def __init__(self) -> None:
    self.constants: list[Constant] = []
    self.instructions: list[Instruction] = []
    self.protos: list[Chunk] = []

    self.name: str = "Unnamed proto"
    self.frst_line: int = 0
    self.last_line: int = 0
    self.numUpvals: int = 0
    self.numParams: int = 0
    self.isVarg: bool = False
    self.maxStack: int = 0

    self.upvalues: list[str] = []
    self.lineNums: list[int] = []
    self.locals: list[Local] = []

  def appendInstruction(self, instr: Instruction) -> None:
    self.instructions.append(instr)

  def appendConstant(self, const: Constant) -> None:
    self.constants.append(const)

  def appendProto(self, proto: "Chunk") -> None:
    self.protos.append(proto)

  def appendLine(self, line: int) -> None:
    self.lineNums.append(line)

  def appendLocal(self, local: Local) -> None:
    self.locals.append(local)

  def appendUpval(self, upval: str) -> None:
    self.upvalues.append(upval)

  def findLocal(self, pc: int) -> Local:
    for local_var in self.locals:
      if local_var.start <= pc and local_var.end >= pc:
        return local_var

    # there's no local information (may have been stripped)
    raise Exception(f"Local not found for PC {pc}")

  def getConstant(self, indx: int) -> Constant:
    return self.constants[indx]

  def print(self) -> None:
    print("\n==== [[" + str(self.name) + "'s constants]] ====\n")
    for i in range(len(self.constants)):
      print(f"{i}: {self.constants[i].toString()}")

    print("\n==== [[" + str(self.name) + "'s locals]] ====\n")
    for i in range(len(self.locals)):
      print(f"R[{i}]: {self.locals[i].name}")

    print("\n==== [[" + str(self.name) + "'s dissassembly]] ====\n")
    for i in range(len(self.instructions)):
      print(f"[{i:3d}] {self.instructions[i].toString():<40s} ; {self.instructions[i].getAnnotation(self)}")

    if len(self.protos) > 0:
      print("\n==== [[" + str(self.name) + "'s protos]] ====\n")
      for z in self.protos:
        z.print()


instr_lookup_tbl = [
  Instruction(InstructionType.ABC, "LOADNIL"),
  Instruction(InstructionType.ABC, "MUL"),
  Instruction(InstructionType.ABC, "SETTABLE"),
  Instruction(InstructionType.ABC, "LE"),
  Instruction(InstructionType.ABC, "CLOSE"),
  Instruction(InstructionType.ABC, "NEWTABLE"),
  Instruction(InstructionType.ABx, "LOADK"),
  Instruction(InstructionType.ABC, "POW"),
  Instruction(InstructionType.ABC, "GETTABLE"),
  Instruction(InstructionType.ABC, "TEST"),
  Instruction(InstructionType.ABC, "LT"),
  Instruction(InstructionType.ABC, "EQ"),
  Instruction(InstructionType.ABC, "MOVE"),
  Instruction(InstructionType.ABx, "SETGLOBAL"),
  Instruction(InstructionType.ABC, "GETUPVAL"),
  Instruction(InstructionType.ABC, "LOADBOOL"),
  Instruction(InstructionType.ABC, "DIV"),
  Instruction(InstructionType.ABC, "RETURN"),
  Instruction(InstructionType.ABC, "ADD"),
  Instruction(InstructionType.ABx, "GETGLOBAL"),
  Instruction(InstructionType.ABC, "CONCAT"),
  Instruction(InstructionType.ABC, "CALL"),
  Instruction(InstructionType.ABC, "TAILCALL"),
  Instruction(InstructionType.ABx, "CLOSURE"),
  Instruction(InstructionType.AsBx, "FORLOOP"),
  Instruction(InstructionType.ABC, "SETLIST"),
  Instruction(InstructionType.AsBx, "FORPREP"),
  Instruction(InstructionType.ABC, "TFORLOOP"),
  Instruction(InstructionType.ABC, "SETUPVAL"),
  Instruction(InstructionType.AsBx, "JMP"),
  Instruction(InstructionType.ABC, "MOD"),
  Instruction(InstructionType.ABC, "NOT"),
  Instruction(InstructionType.ABC, "SELF"),
  Instruction(InstructionType.ABC, "UNM"),
  Instruction(InstructionType.ABC, "TESTSET"),
  Instruction(InstructionType.ABC, "LEN"),
  Instruction(InstructionType.ABC, "SUB"),
  Instruction(InstructionType.ABC, "VARARG"),
]


# at [p]osition, with [s]ize of bits
def get_bits(num: int, p: int, s: int) -> int:
  return (num >> p) & (~((~0) << s))


# set bits from data to num at [p]osition, with [s]ize of bits
def set_bits(num: int, data: int, p: int, s: int) -> int:
  return (num & (~((~((~0) << s)) << p))) | ((data << p) & ((~((~0) << s)) << p))


def _decode_instr(data: int) -> Instruction:
  opcode = get_bits(data, 26, 6)
  if opcode >= len(instr_lookup_tbl):
    raise Exception(f"Unknown XDI opcode! [{opcode}]")

  template = instr_lookup_tbl[opcode]
  instr = Instruction(template.type, template.name)

  instr.opcode = Opcodes(opcode)
  instr.A = get_bits(data, 0, 8)

  if instr.type == InstructionType.ABC:
    instr.B = get_bits(data, 8, 9)
    instr.C = get_bits(data, 17, 9)
    # XDI encoding flips B/C semantics for table-read family opcodes.
    if opcode in (Opcodes.GETTABLE, Opcodes.SELF):
      instr.B, instr.C = instr.C, instr.B
  elif instr.type == InstructionType.ABx:
    instr.B = get_bits(data, 8, 18)
  elif instr.type == InstructionType.AsBx:
    instr.B = get_bits(data, 8, 18) - 131071

  return instr


# returns a u32 instruction
def _encode_instr(instr: Instruction) -> int:
  data = 0

  # encode instruction (inverse of XDI decode bit layout)
  data = set_bits(data, int(instr.opcode), 26, 6)
  data = set_bits(data, instr.A, 0, 8)
  if instr.type == InstructionType.ABC:
    data = set_bits(data, instr.B, 8, 9)
    data = set_bits(data, instr.C, 17, 9)
  elif instr.type == InstructionType.ABx:
    data = set_bits(data, instr.B, 8, 18)
  elif instr.type == InstructionType.AsBx:
    data = set_bits(data, instr.B + 131071, 8, 18)

  return data


class LuaUndump:
  rootChunk: Chunk

  def __init__(self) -> None:
    self.index = 0

  def _loadBlock(self, sz: int) -> bytearray:
    if self.index + sz > len(self.bytecode):
      raise Exception("Malformed bytecode!")

    temp = bytearray(self.bytecode[self.index : self.index + sz])
    self.index = self.index + sz
    return temp

  def _get_byte(self) -> int:
    return self._loadBlock(1)[0]

  def _get_uint32(self) -> int:
    order = "big" if self.big_endian else "little"
    return int.from_bytes(self._loadBlock(4), byteorder=order, signed=False)

  def _get_uint(self) -> int:
    order = "big" if self.big_endian else "little"
    return int.from_bytes(self._loadBlock(self.int_size), byteorder=order, signed=False)

  def _get_size_t(self) -> int:
    order = "big" if self.big_endian else "little"
    return int.from_bytes(self._loadBlock(self.size_t), byteorder=order, signed=False)

  def _get_double(self) -> int:
    order = ">d" if self.big_endian else "<d"
    return struct.unpack(order, self._loadBlock(self.l_number_size))[0]

  def _get_string(self) -> str:
    return self._get_xdi_string()

  def _get_xdi_string(self) -> str:
    size = self._get_size_t()
    if size == 0:
      return ""
    if size < 10:
      raise Exception(f"Malformed XDI string size! [{size}]")

    # XDI stores (payload + NULL + 10-byte overhead); loader reads size-10 bytes.
    payload = self._loadBlock(size - 10)
    return bytes(payload[:-1] if payload[-1] == 0 else payload).decode("utf-8", errors="replace")

  def decode_chunk(self) -> Chunk:
    chunk = Chunk()

    # chunk meta info
    chunk.name = self._get_string()
    chunk.frst_line = self._get_uint()
    chunk.last_line = self._get_uint()
    chunk.numUpvals = self._get_byte()
    chunk.numParams = self._get_byte()
    chunk.isVarg = self._get_byte() != 0
    chunk.maxStack = self._get_byte()

    # parse instructions
    num = self._get_uint()
    for i in range(num):
      raw_instr = self._get_uint32()
      instr = _decode_instr(raw_instr)
      instr.raw = raw_instr
      chunk.appendInstruction(instr)

    # get constants
    num = self._get_uint()
    for i in range(num):
      type = self._get_byte()

      if type == 0:  # nil
        constant = Constant(ConstType.NIL, None)
      elif type == 1:  # bool
        constant = Constant(ConstType.BOOL, (self._get_byte() != 0))
      elif type == 3:  # number
        constant = Constant(ConstType.NUMBER, self._get_double())
      elif type == 4:  # string
        constant = Constant(ConstType.STRING, self._get_string())
      else:
        raise Exception(f"Unknown Datatype! [{type}]")

      chunk.appendConstant(constant)

    # parse protos
    num = self._get_uint()
    for i in range(num):
      chunk.appendProto(self.decode_chunk())

    # debug stuff, maybe i'll add this to chunks to have better disassembly annotation in the future?
    # eh, for now just consume the bytes.

    # line numbers
    num = self._get_uint()
    for i in range(num):
      self._get_uint()

    # locals
    num = self._get_uint()
    for i in range(num):
      name = self._get_string()  # local name
      start = self._get_uint()  # local start PC
      end = self._get_uint()  # local end PC
      chunk.appendLocal(Local(name, start, end))

    # upvalues
    num = self._get_uint()
    for i in range(num):
      chunk.appendUpval(self._get_string())  # upvalue name

    return chunk

  def decode_rawbytecode(self, rawbytecode: bytes | bytearray | array.array) -> Chunk:
    # bytecode sanity checks
    if not rawbytecode[0:4] == _XDIMAGIC:
      raise Exception("XDI bytecode expected!")

    bytecode = bytearray(rawbytecode)
    return self.decode_bytecode(bytecode)

  def decode_bytecode(self, bytecode: bytes | bytearray) -> Chunk:
    self.bytecode = bytecode

    # aligns index, skips header
    self.index = 4

    self.vm_version = self._get_byte()
    self.bytecode_format = self._get_byte()
    self.big_endian = self._get_byte() == 0
    self.int_size = self._get_byte()
    self.size_t = self._get_byte()
    self.instr_size = self._get_byte()  # gets size of instructions
    self.l_number_size = self._get_byte()  # size of lua_Number
    self.integral_flag = (
      self._get_byte()
    )  # is lua_Number defined as an int? false = float/double, true = int/long/short/etc.

    self.rootChunk = self.decode_chunk()
    return self.rootChunk

  def loadFile(self, luaCFile: str) -> Chunk:
    with open(luaCFile, "rb") as luac_file:
      bytecode = luac_file.read()
      return self.loadBytes(bytecode)

  def loadBytes(self, bytecode: bytes | bytearray | array.array) -> Chunk:
    return self.decode_rawbytecode(bytecode)

  def print_dissassembly(self) -> None:
    self.rootChunk.print()


class LuaDump:
  def __init__(self, rootChunk: Chunk) -> None:
    self.rootChunk = rootChunk
    self.bytecode = bytearray()

    # header info
    self.vm_version = 0x01
    self.bytecode_format = 0x00
    self.big_endian = False

    # data sizes
    self.int_size = 4
    self.size_t = 8
    self.instr_size = 4
    self.l_number_size = 8
    self.integral_flag = False  # lua_Number is a double

  def _writeBlock(self, data: bytes) -> None:
    self.bytecode += bytearray(data)

  def _set_byte(self, b: int) -> None:
    self.bytecode.append(b)

  def _set_uint32(self, i: int) -> None:
    order = "big" if self.big_endian else "little"
    self._writeBlock(i.to_bytes(4, order, signed=False))

  def _set_uint(self, i: int) -> None:
    order = "big" if self.big_endian else "little"
    self._writeBlock(i.to_bytes(self.int_size, order, signed=False))

  def _set_size_t(self, i: int) -> None:
    order = "big" if self.big_endian else "little"
    self._writeBlock(i.to_bytes(self.size_t, order, signed=False))

  def _set_double(self, f: float) -> None:
    order = ">d" if self.big_endian else "<d"
    self._writeBlock(struct.pack(order, f))

  def _set_string(self, string: str) -> None:
    self._set_size_t(len(string) + 11)
    self._writeBlock(string.encode("utf-8"))
    self._set_byte(0x00)  # write null terminator
    self._writeBlock(b"\x00" * 10)

  def _dumpChunk(self, chunk: Chunk) -> None:
    # write meta info
    self._set_string(chunk.name)
    self._set_uint(chunk.frst_line)
    self._set_uint(chunk.last_line)
    self._set_byte(chunk.numUpvals)
    self._set_byte(chunk.numParams)
    self._set_byte(1 if chunk.isVarg else 1)
    self._set_byte(chunk.maxStack)

    # write instructions
    self._set_uint(len(chunk.instructions))
    for inst in chunk.instructions:
      self._set_uint32(_encode_instr(inst))

    # write constants
    self._set_uint(len(chunk.constants))
    for constant in chunk.constants:
      # write constant data
      if constant.type == ConstType.NIL:
        self._set_byte(0)
      elif constant.type == ConstType.BOOL:
        self._set_byte(1)
        self._set_byte(1 if constant.data else 0)
      elif constant.type == ConstType.NUMBER:  # number
        assert isinstance(constant.data, float)
        self._set_byte(3)
        self._set_double(constant.data)
      elif constant.type == ConstType.STRING:  # string
        assert isinstance(constant.data, str)
        self._set_byte(4)
        self._set_string(constant.data)
      else:
        raise Exception(f"Unknown Datatype! [{str(constant.type)}]")

    # write child protos
    self._set_uint(len(chunk.protos))
    for p in chunk.protos:
      self._dumpChunk(p)

    # write line numbers
    self._set_uint(len(chunk.lineNums))
    for line_num in chunk.lineNums:
      self._set_uint(line_num)

    # write locals
    self._set_uint(len(chunk.locals))
    for local_var in chunk.locals:
      self._set_string(local_var.name)
      self._set_uint(local_var.start)
      self._set_uint(local_var.end)

    # write upvals
    self._set_uint(len(chunk.upvalues))
    for u in chunk.upvalues:
      self._set_string(u)

  def _dumpHeader(self) -> None:
    self._writeBlock(_XDIMAGIC)

    # write header info
    self._set_byte(self.vm_version)
    self._set_byte(self.bytecode_format)
    self._set_byte(0 if self.big_endian else 1)
    self._set_byte(self.int_size)
    self._set_byte(self.size_t)
    self._set_byte(self.instr_size)
    self._set_byte(self.l_number_size)
    self._set_byte(self.integral_flag)

  def dump(self) -> bytearray:
    self._dumpHeader()
    self._dumpChunk(self.rootChunk)

    return self.bytecode
