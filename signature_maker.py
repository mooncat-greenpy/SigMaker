import pefile
import os
import sys
import json


def make_sig_table(path, offset, size, sig_table):
    if os.path.getsize(path) <= offset:
        return
    f = open(path, "rb")
    f.seek(offset)
    data = f.read(size)
    f.close()

    for i in range(len(data)):
        if data[i] not in sig_table[i]:
            sig_table[i][data[i]] = {"count": 1, "paths": [path]}
        else:
            sig_table[i][data[i]]["count"] += 1
            sig_table[i][data[i]]["paths"].append(path)


def make_signature(sig_table, min_file_num):
    signature = ""
    paths = []
    for i in sig_table:
        value = -1
        tmp_max_num = 0
        for j in i:
            if len(paths):
                tmp_paths = list(set(i[j]["paths"]) & set(paths))
            else:
                tmp_paths = i[j]["paths"]

            if len(tmp_paths) > min_file_num and len(tmp_paths) > tmp_max_num:
                value = int(j)
                tmp_max_num = len(tmp_paths)
                paths = tmp_paths

        if value >= 0:
            signature += "%02x" % value
        else:
            signature += "??"
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


def get_signature(path, get_offset_callback, min_file_num):
    size = 0x20
    sig_table = init_sig_table(size)

    json_path = os.path.basename(path) + ".json"
    if os.path.exists(json_path):
        with open(json_path, "r") as f:
            sig_table = json.load(f)
        return make_signature(sig_table, min_file_num)

    for i in os.listdir(path):
        new_path = os.path.join(path, i)
        offset = get_offset_callback(new_path)
        make_sig_table(new_path, offset, size, sig_table)

    with open(json_path, "w") as f:
        json.dump(sig_table, f, indent=4)

    return make_signature(sig_table, min_file_num)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python signature_maker.py path [min file num]")
        exit()
    path = sys.argv[1]
    min_file_num = 0
    if len(sys.argv) >= 3 and sys.argv[2].isdigit():
        min_file_num = int(sys.argv[2])
    callback = get_pe_entry_point_offset
    signature = get_signature(path, callback, min_file_num)

    print(path)
    print(signature)
