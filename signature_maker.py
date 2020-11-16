import pefile
import os
import sys


def make_sig_table(path, offset, size, sig_table):
    if os.path.getsize(path) <= offset:
        return
    f = open(path, "rb")
    f.seek(offset)
    data = f.read(size)
    f.close()

    for i in range(len(data)):
        if data[i] not in sig_table[i]:
            sig_table[i][data[i]] = 1
        else:
            sig_table[i][data[i]] += 1


def make_signature(sig_table):
    signature = ""
    for i in sig_table:
        if len(i) == 1:
            signature += "%02x" % list(i.keys())[0]
        elif len(i) > 1:
            signature += "??"
        else:
            return signature
    return signature


def init_sig_table(size):
    sig_table = []
    for i in range(size):
        sig_table.append({})
    return sig_table


def get_pe_entry_point_offset(path):
    pe = pefile.PE(path)
    physical_ep = pe.get_physical_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    pe.close()
    return physical_ep


def get_signature(path, get_offset_callback):
    size = 0x20
    sig_table = init_sig_table(size)
    for i in os.listdir(path):
        new_path = os.path.join(path, i)
        offset = get_offset_callback(new_path)
        make_sig_table(new_path, offset, size, sig_table)
    return make_signature(sig_table)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python signature_maker.py path")
        exit()
    path = sys.argv[1]
    callback = get_pe_entry_point_offset
    signature = get_signature(path, callback)

    print(path)
    print(signature)
