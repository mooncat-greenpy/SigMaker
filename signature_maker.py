import pefile
import os
import sys
import json
from logging import basicConfig, getLogger, DEBUG, INFO, WARN, ERROR, CRITICAL

basicConfig(
    format="[%(asctime)s] %(name)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=WARN,
)
logger = getLogger("SigMaker")


class SigMaker:
    DATASET_DATA_SIZE = 0x20

    def __init__(self, option="full", min_file_num=0):
        self.option = option
        self.min_file_num = min_file_num

        self.signature_list = []
        self.max_paths = 0
        self.dataset_table = []

    def make_signature(self):
        if self.option == "full":
            return self.make_signature_full()
        if self.option == "light":
            return self.make_signature_light()

    def make_signature_full(self):
        paths = []
        for i in self.dataset_table[0]:
            paths.extend(self.dataset_table[0][i]["paths"])

        self.make_signature_recur(0, "", paths)

        return self.signature_list

    def make_signature_recur(self, index, signature, paths):
        if len(self.dataset_table) <= index:
            if len(paths) >= self.max_paths:
                self.signature_list.append((signature, paths))
                self.max_paths = len(paths)
            return

        for i in self.dataset_table[index]:
            next_paths = list(set(paths) & set(self.dataset_table[index][i]["paths"]))
            if len(next_paths) <= 0:
                continue
            if len(paths) >= self.max_paths:
                self.make_signature_recur(
                    index + 1,
                    "%s%02x" % (signature, int(i)),
                    next_paths,
                )

        if len(paths) > self.max_paths:
            self.make_signature_recur(index + 1, "%s??" % (signature), paths)

    def make_signature_light(self):
        signature = ""
        paths = []
        for i in self.dataset_table:
            value = -1
            tmp_max_num = 0
            for j in i:
                if len(paths):
                    tmp_paths = list(set(i[j]["paths"]) & set(paths))
                else:
                    tmp_paths = i[j]["paths"]

                if len(tmp_paths) > self.min_file_num and len(tmp_paths) > tmp_max_num:
                    value = int(j)
                    tmp_max_num = len(tmp_paths)
                    paths = tmp_paths

            if value >= 0:
                signature += "%02x" % value
            else:
                signature += "??"

        self.signature_list = [(signature, paths)]
        return self.signature_list

    def make_dataset(self, path, get_offset_callback):
        self.init_dataset_table()
        self.collect_dataset_recur(path, get_offset_callback)

    def add_dataset(self, path, get_offset_callback):
        self.collect_dataset_recur(path, get_offset_callback)

    def load_dataset(self, json_path):
        if not os.path.exists(json_path):
            logger.warning("No such a file %s" % path)
            return
        with open(json_path, "r") as f:
            self.dataset_table = json.load(f)

    def save_dataset(self, json_path):
        with open(json_path, "w") as f:
            json.dump(self.dataset_table, f, indent=4)

    def init_dataset_table(self):
        self.dataset_table = []
        for i in range(self.DATASET_DATA_SIZE):
            self.dataset_table.append({})

    def collect_dataset_recur(self, path, get_offset_callback):
        for i in os.listdir(path):
            new_path = os.path.join(path, i)
            if os.path.isdir(new_path):
                self.collect_dataset_recur(new_path, get_offset_callback)
            else:
                offset = get_offset_callback(new_path)
                self.make_dataset_table(new_path, offset)

    def make_dataset_table(self, path, offset):
        if offset == None or os.path.getsize(path) <= offset:
            logger.warning("Offset is invalid")
            return
        f = open(path, "rb")
        f.seek(offset)
        data = f.read(self.DATASET_DATA_SIZE)
        f.close()

        for i in range(len(data)):
            if data[i] not in self.dataset_table[i]:
                self.dataset_table[i][data[i]] = {"count": 1, "paths": [path]}
            else:
                self.dataset_table[i][data[i]]["count"] += 1
                self.dataset_table[i][data[i]]["paths"].append(path)


# Return file offset or None
def get_pe_entry_point_offset(path, machine):
    physical_ep = None
    try:
        pe = pefile.PE(path)
        if not pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE[machine]:
            logger.warning("%s machine is not %s" % (path, machine))
            return None
        physical_ep = pe.get_physical_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe.close()
    except Exception as e:
        logger.error(e.__str__())
        physical_ep = None
    return physical_ep


def get_pe_i386_entry_point_offset(path):
    return get_pe_entry_point_offset(path, "IMAGE_FILE_MACHINE_I386")


def get_pe_ia64_entry_point_offset(path):
    return get_pe_entry_point_offset(path, "IMAGE_FILE_MACHINE_IA64")


def get_pe_amd64_entry_point_offset(path):
    return get_pe_entry_point_offset(path, "IMAGE_FILE_MACHINE_AMD64")


def get_zero_offset(path):
    return 0


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
    callback = get_pe_i386_entry_point_offset
    sig_maker = SigMaker(option, min_file_num)
    sig_maker.make_dataset(path, callback)
    signatures = sig_maker.make_signature()

    for i in signatures:
        print(i[0], "  ", len(i[1]))
