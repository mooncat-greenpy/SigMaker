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


signature_list = []
max_paths = 0


def make_signature_recur(sig_table, index, signature, paths):
    global signature_list
    global max_paths
    if len(sig_table) <= index:
        if len(paths) >= max_paths:
            signature_list.append((signature, paths))
            max_paths = len(paths)
        return (signature, paths)
    for i in sig_table[index]:
        if len(list(set(paths) & set(sig_table[index][i]["paths"]))) <= 1:
            continue
        if len(paths) >= max_paths:
            make_signature_recur(
                sig_table,
                index + 1,
                "%s%02x" % (signature, int(i)),
                list(set(paths) & set(sig_table[index][i]["paths"])),
            )

    if len(paths) > max_paths:
        make_signature_recur(sig_table, index + 1, "%s??" % (signature), paths)


def make_signature_full(sig_table):
    global signature_list
    paths = []
    for i in sig_table[0]:
        paths.extend(sig_table[0][i]["paths"])

    make_signature_recur(sig_table, 0, "", paths)

    return signature_list


def make_signature_light(sig_table, min_file_num):
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
    return [(signature, paths)]


def make_signature(sig_table, option="full", min_file_num=0):
    if option == "full":
        return make_signature_full(sig_table)
    if option == "light":
        return make_signature_light(sig_table, min_file_num)


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


def collect_dataset_recur(path, get_offset_callback, sig_table, size):
    for i in os.listdir(path):
        new_path = os.path.join(path, i)
        if os.path.isdir(new_path):
            collect_dataset_recur(new_path, get_offset_callback, sig_table, size)
        else:
            offset = get_offset_callback(new_path)
            make_sig_table(new_path, offset, size, sig_table)


def get_signature(path, get_offset_callback, option, min_file_num=0):
    size = 0x20
    sig_table = init_sig_table(size)

    json_path = os.path.basename(path) + ".json"
    if os.path.exists(json_path):
        with open(json_path, "r") as f:
            sig_table = json.load(f)
        return make_signature(sig_table, option=option, min_file_num=min_file_num)

    collect_dataset_recur(path, get_offset_callback, sig_table, size)

    with open(json_path, "w") as f:
        json.dump(sig_table, f, indent=4)

    return make_signature(sig_table, option=option, min_file_num=min_file_num)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python signature_maker.py path [option] [min file num]")
        exit()
    path = sys.argv[1]
    option = "full"
    if len(sys.argv) >= 3:
        option = sys.argv[2]
    min_file_num = 0
    if len(sys.argv) >= 4 and sys.argv[3].isdigit():
        min_file_num = int(sys.argv[3])
    callback = get_pe_entry_point_offset
    signatures = get_signature(path, callback, option, min_file_num)

    for i in signatures:
        print(i[0], "  ", len(i[1]))
