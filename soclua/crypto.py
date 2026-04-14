# evidence: GameAssembly.dll LuaFileUtils::ReadZipFile
def to_xfc(data: bytes) -> bytes:
  out = bytearray(data)

  xor_key = bytes.fromhex("3517F1C355786439404277591233CB7BB9")
  for i in range(len(out)):
    out[i] ^= xor_key[i % len(xor_key)]

  if out[:4] == b"\x01XFC":
    return bytes(out)

  raise RuntimeError("[-] bytes-to-XFC failed.")


# evidence: slua.dll luaZ_read
def to_xdi(data: bytes) -> bytes:
  out = bytearray(len(data))

  for v8 in range(len(data)):
    v16 = data[v8]

    if v8 <= 1:
      out[v8] = v16
    else:
      v10 = (539034887 * v8) & 0xFFFFFFFFFFFFFFFF
      v14 = v8 % 3

      if v14 == 1:
        byte2 = (v10 >> 16) & 0xFF
        key = (byte2 - v8) & 0xFF
        out[v8] = key ^ v16
      elif v14 == 2:
        v15 = ((v10 >> 21) | v8) & 0xFF
        out[v8] = v15 ^ v16
      else:  # v14 == 0
        v15 = ((v10 >> 28) + (v10 & 1) + v8) & 0xFF
        out[v8] = v15 ^ v16

  if out[:4] == b"\x01XDI":
    return bytes(out)

  raise RuntimeError("[-] XFC-to-XDI failed.")
