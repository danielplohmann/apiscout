import copy
import json
import logging
import os
import random
import struct
import tempfile
import unittest

from apiscout.ApiScout import ApiScout
from apiscout.LoadAddresses import (
    SOURCE_IMAGES,
    SOURCE_MINIDUMP,
    SOURCE_MODULES,
    DllPlacer,
    dll_file_name,
    find_dll_images,
    match_images,
    match_load_addresses,
    normalize_dll_path,
    read_load_addresses,
)
from tests.testMinidump import build_minidump, page, run

THIS_DIR = os.path.abspath(os.path.dirname(__file__))
DBS_DIR = os.path.join(THIS_DIR, "..", "dbs")
WIN11_DB = os.path.join(DBS_DIR, "win11_pro_26h2_example.json")


def build_dll_image(name, exports, bitness=32, size=0x3000, export_directory=True):
    """a DLL as it is laid out in memory: header page, export directory at 0x1000, name at 0x1100, export address
    table at 0x1200. exports: {ordinal: RVA}"""
    image = bytearray(size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    optional_header_size = 0xE0 if bitness == 32 else 0xF0
    struct.pack_into(
        "<HHIIIHH", image, 0x84, 0x14C if bitness == 32 else 0x8664, 0, 0, 0, 0, optional_header_size, 0x2102
    )
    struct.pack_into("<H", image, 0x98, 0x10B if bitness == 32 else 0x20B)
    directory_offset = 0x98 + (0x60 if bitness == 32 else 0x70)
    if export_directory:
        struct.pack_into("<II", image, directory_offset, 0x1000, 0x100)
        first, last = min(exports), max(exports)
        struct.pack_into("<IIHHIIIIIII", image, 0x1000, 0, 0, 0, 0, 0x1100, first, last - first + 1, 0, 0x1200, 0, 0)
        image[0x1100 : 0x1100 + len(name) + 1] = name.encode() + b"\x00"
        for ordinal, rva in exports.items():
            struct.pack_into("<I", image, 0x1200 + 4 * (ordinal - first), rva)
    return bytes(image)


def write_db(directory, dlls, name="db.json", os_name="Windows 10"):
    path = os.path.join(directory, name)
    with open(path, "w") as f_db:
        json.dump({"aslr_offsets": True, "dlls": dlls, "os_name": os_name, "os_version": "10.0.1"}, f_db)
    return path


def read_db(path):
    with open(path) as f_db:
        return json.load(f_db)


def dll_entry(path, base, bitness, exports, load_address=None):
    """a DLL of an API DB, built at base and loaded at load_address by the boot the DB was built in"""
    return {
        "filepath": path,
        "base_address": base,
        "bitness": bitness,
        "version": "10.0.1",
        "aslr_offset": base - load_address if load_address else 0,
        "exports": [{"address": rva, "name": f"Api{ordinal}", "ordinal": ordinal} for ordinal, rva in exports.items()],
    }


class MatchingTestSuite(unittest.TestCase):
    """the matching of load addresses is the one of DatabaseBuilder.applyLoadAddresses, whose copy it is"""

    def _builderOffsets(self, dlls, addresses):
        from apiscout.db_builder import DatabaseBuilder

        api_db = {"dlls": copy.deepcopy(dlls)}
        DatabaseBuilder.DatabaseBuilder().applyLoadAddresses(api_db, addresses)
        return {
            key: dll["base_address"] - dll["aslr_offset"] for key, dll in api_db["dlls"].items() if dll["aslr_offset"]
        }

    def testSameResultsAsTheDbBuilder(self):
        scenarios = [
            (
                {
                    "64": {"filepath": "/mnt/win/Windows/System32/kernel32.dll", "base_address": 0x180000000},
                    "32": {"filepath": "/mnt/win/Windows/SysWOW64/kernel32.dll", "base_address": 0x68900000},
                    "n64": {"filepath": "/mnt/win/Windows/System32/ntdll.dll", "base_address": 0x180000000},
                },
                [("system32/kernel32.dll", 0x7FFB11110000), ("syswow64/kernel32.dll", 0x75990000)],
            ),
            (
                {
                    "64": {
                        "filepath": "C:\\Windows\\System32\\kernel32.dll",
                        "base_address": 0x180000000,
                        "bitness": 64,
                    },
                    "32": {
                        "filepath": "C:\\Windows\\SysWOW64\\kernel32.dll",
                        "base_address": 0x6B800000,
                        "bitness": 32,
                    },
                },
                [("system32/kernel32.dll", 0x75990000)],
            ),
            (
                {
                    "64": {
                        "filepath": "C:\\Windows\\System32\\kernel32.dll",
                        "base_address": 0x180000000,
                        "bitness": 64,
                    },
                    "32": {
                        "filepath": "C:\\Windows\\SysWOW64\\kernel32.dll",
                        "base_address": 0x6B800000,
                        "bitness": 32,
                    },
                    "n64": {"filepath": "C:\\Windows\\System32\\ntdll.dll", "base_address": 0x180000000, "bitness": 64},
                },
                [("system32/kernel32.dll", 0x77A10000), ("system32/ntdll.dll", 0x7FFB11110000)],
            ),
            (
                {
                    "flat": {"filepath": "/copy/kernel32.dll", "base_address": 0x180000000, "bitness": 64},
                    "other": {"filepath": "/copy/ntdll.dll", "base_address": 0x180000000, "bitness": 64},
                },
                [
                    ("system32/kernel32.dll", 0x7FFA10000000),
                    ("system32/ntdll.dll", 0x7FFA20000000),
                    ("syswow64/ntdll.dll", 0x77000000),
                ],
            ),
            (
                {
                    "k64": {"filepath": "C:/Windows/System32/kernel32.dll", "base_address": 0x180000000, "bitness": 64},
                    "k32": {"filepath": "C:/Windows/SysWOW64/kernel32.dll", "base_address": 0x6B800000, "bitness": 32},
                    "t64": {"filepath": "C:/Program Files/ink/tiptsf.dll", "base_address": 0x180000000, "bitness": 64},
                    "t32": {
                        "filepath": "C:/Program Files (x86)/ink/tiptsf.dll",
                        "base_address": 0x10000000,
                        "bitness": 32,
                    },
                    "o64": {"filepath": "C:/Tools/x64/other.dll", "base_address": 0x180000000, "bitness": 64},
                },
                [("system32/kernel32.dll", 0x75990000), ("ink/tiptsf.dll", 0x6F000000), ("app/other.dll", 0x6E000000)],
            ),
            (
                {
                    "k64": {"filepath": "C:/Windows/System32/kernel32.dll", "base_address": 0x180000000, "bitness": 64},
                    "k32": {"filepath": "C:/Windows/SysWOW64/kernel32.dll", "base_address": 0x6B800000, "bitness": 32},
                    "t64": {"filepath": "C:/Program Files/ink/tiptsf.dll", "base_address": 0x180000000, "bitness": 64},
                    "t32": {
                        "filepath": "C:/Program Files (x86)/ink/tiptsf.dll",
                        "base_address": 0x10000000,
                        "bitness": 32,
                    },
                },
                [("system32/kernel32.dll", 0x7FFB11110000), ("ink/tiptsf.dll", 0x6F000000)],
            ),
        ]
        for dlls, addresses in scenarios:
            for dll in dlls.values():
                dll.setdefault("aslr_offset", 0)
            expected = self._builderOffsets(dlls, addresses)
            self.assertEqual(expected, match_load_addresses(dlls, addresses), dlls)
        # the scenarios are not all empty
        self.assertTrue(self._builderOffsets(*scenarios[0]))

    def testSameModuleListFormatAsTheDbBuilder(self):
        from apiscout.db_builder import DatabaseBuilder

        content = '# list\n0x7ffb11110000 "C:\\Windows\\System32\\kernel32.dll"\r\n75990000 C:\\Windows\\SysWOW64\\kernel32.dll\r\nzz bad\r\n\r\n'
        expected = [("system32/kernel32.dll", 0x7FFB11110000), ("syswow64/kernel32.dll", 0x75990000)]
        with tempfile.TemporaryDirectory() as directory:
            for encoding in ("utf-8", "utf-8-sig", "utf-16"):
                path = os.path.join(directory, encoding)
                with open(path, "w", encoding=encoding, newline="") as f_addresses:
                    f_addresses.write(content)
                self.assertEqual(expected, read_load_addresses(path))
                self.assertEqual(expected, DatabaseBuilder.read_load_addresses(path))
        self.assertEqual("system32/kernel32.dll", normalize_dll_path("/mnt/Windows/System32//kernel32.dll"))

    def testWarnsAboutThe32bitListOfASystem32OnlyCopy(self):
        """without SysWOW64, the list of a 32bit process is applied to the 64bit DLLs: warn, both in the DB builder
        and at scan time. 64bit ntdll, kernel32 and user32 are loaded below 4 GB by Windows 7, which is no reason."""
        from apiscout.db_builder import DatabaseBuilder

        def dlls(*names):
            return {
                name: {
                    "filepath": f"C:\\Windows\\System32\\{name}",
                    "base_address": 0x180000000,
                    "bitness": 64,
                    "aslr_offset": 0,
                }
                for name in names
            }

        def warnings_of(dlls, addresses, lists=1):
            records = []
            with self.assertLogs(level="DEBUG") as logs:
                # something to be logged, assertLogs fails without a record
                logging.getLogger().debug("start")
                builder_offsets = self._builderOffsets(dlls, addresses)
                self.assertEqual(builder_offsets, match_load_addresses(dlls, addresses))
                placer = DllPlacer()
                for number in range(lists):
                    placer.addModuleList(f"list {number}", addresses)
                self.assertEqual(builder_offsets, placer({"dlls": dlls}))
            for record in logs.records:
                if record.levelno >= logging.WARNING and "got a load address below 4 GB" in record.getMessage():
                    records.append((record.name, record.getMessage()))
            return records

        names = ("ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll", "rpcrt4.dll", "sechost.dll", "msvcrt.dll")
        list_of_32bit_process = [
            ("system32/" + name, 0x77000000 + 0x100000 * index) for index, name in enumerate(names)
        ]
        found = warnings_of(dlls(*names), list_of_32bit_process)
        self.assertEqual(
            ["apiscout.LoadAddresses", "apiscout.db_builder.DatabaseBuilder"], sorted(name for name, _ in found)
        )
        # several module lists for one DB are one warning of the scan, the placements are what it is about
        found = warnings_of(dlls(*names), list_of_32bit_process, lists=3)
        self.assertEqual(
            ["apiscout.LoadAddresses", "apiscout.db_builder.DatabaseBuilder"], sorted(name for name, _ in found)
        )
        for _, message in found:
            self.assertIn("4 64bit DLLs got a load address below 4 GB", message)
            self.assertIn("advapi32.dll 0x77300000, msvcrt.dll 0x77600000, rpcrt4.dll 0x77400000, ...", message)
            self.assertNotIn("ntdll", message)
        # a 64bit process on Windows 7: three DLLs below 4 GB, the others high
        list_of_64bit_process = [
            ("system32/" + name, 0x77000000 + 0x100000 * index) for index, name in enumerate(names[:3])
        ]
        list_of_64bit_process += [
            ("system32/" + name, 0x7FEFD000000 + 0x100000 * index) for index, name in enumerate(names[3:])
        ]
        self.assertEqual([], warnings_of(dlls(*names), list_of_64bit_process))
        # with SysWOW64 in the DB the list of a 32bit process is applied to the 32bit DLLs, nothing to warn about
        both = dlls(*names)
        both["wow"] = {
            "filepath": "C:\\Windows\\SysWOW64\\advapi32.dll",
            "base_address": 0x10000000,
            "bitness": 32,
            "aslr_offset": 0,
        }
        self.assertEqual([], warnings_of(both, list_of_32bit_process))
        del DatabaseBuilder

    def testFileNameOfDll(self):
        self.assertEqual("midimap.dll", dll_file_name("32_10.0.26100.1882_midimap.dll_0x6b700000", {}))
        self.assertEqual(
            "kernel32.dll", dll_file_name("64_kernel32.dll", {"filepath": "C:\\Windows\\System32\\KERNEL32.dll"})
        )


class DllImageTestSuite(unittest.TestCase):
    def _db(self, directory):
        dlls = {
            "32_10.0.1_KernelBase.dll_0x10000000": dll_entry(
                "C:\\Windows\\SysWOW64\\KernelBase.dll", 0x10000000, 32, {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
            ),
            "64_10.0.1_KernelBase.dll_0x180000000": dll_entry(
                "C:\\Windows\\System32\\KernelBase.dll", 0x180000000, 64, {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
            ),
        }
        return write_db(directory, dlls)

    def testFindsTheImagesOfADump(self):
        exports = {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
        dump = (
            bytes(0x1000)
            + build_dll_image("KERNELBASE.dll", exports)
            + bytes(0x1000)
            + build_dll_image("x.dll", {1: 0x1500}, bitness=64)
        )
        images = find_dll_images(dump, 0x400000)
        self.assertEqual(
            [(0x401000, "kernelbase.dll", 32, exports), (0x405000, "x.dll", 64, {1: 0x1500})],
            [(image.load_address, image.name, image.bitness, image.exports) for image in images],
        )

    def testPlacesTheDllByItsExports(self):
        exports = {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
        with tempfile.TemporaryDirectory() as directory:
            db_path = self._db(directory)
            api_db = read_db(db_path)
            # at the address of a boot, 32bit
            images = find_dll_images(bytes(0x1000) + build_dll_image("KernelBase.dll", exports), 0x70000000)
            self.assertEqual({"32_10.0.1_KernelBase.dll_0x10000000": 0x70001000}, match_images(api_db["dlls"], images))
            # the 64bit DLL of the same name for a 64bit image
            images = find_dll_images(bytes(0x1000) + build_dll_image("KernelBase.dll", exports, 64), 0x7FF000000000)
            self.assertEqual(
                {"64_10.0.1_KernelBase.dll_0x180000000": 0x7FF000001000}, match_images(api_db["dlls"], images)
            )
            # another version of the DLL: same name, other RVAs
            images = find_dll_images(
                bytes(0x1000) + build_dll_image("KernelBase.dll", {383: 0x6B00, 384: 0x6B40, 390: 0x7100}), 0
            )
            self.assertEqual({}, match_images(api_db["dlls"], images))
            # another DLL, no export directory, an export address table beyond the dump
            for image in (
                build_dll_image("other.dll", exports),
                build_dll_image("KernelBase.dll", exports, export_directory=False),
                build_dll_image("KernelBase.dll", exports)[:0x1210],
            ):
                self.assertEqual({}, match_images(api_db["dlls"], find_dll_images(bytes(0x1000) + image, 0)))

    def testExportDirectoryNameIsNotTheFileName(self):
        """the export directory of kernel.appcore.dll names appcore.dll: found by its exports, if they tell it apart"""
        exports = {ordinal: 0x1100 + 0x10 * ordinal for ordinal in range(1, 11)}
        dlls = {
            "64_10.0.1_kernel.appcore.dll_0x180000000": dll_entry(
                "C:\\Windows\\System32\\kernel.appcore.dll", 0x180000000, 64, exports
            ),
            "64_10.0.1_other.dll_0x180000000": dll_entry(
                "C:\\Windows\\System32\\other.dll",
                0x180000000,
                64,
                {ordinal: 0x2000 + ordinal for ordinal in range(1, 11)},
            ),
        }
        images = find_dll_images(bytes(0x1000) + build_dll_image("appcore.dll", exports, 64), 0x7FF000000000)
        self.assertEqual({"64_10.0.1_kernel.appcore.dll_0x180000000": 0x7FF000001000}, match_images(dlls, images))
        # the same exports twice in the DB: no telling which DLL it is
        dlls["64_10.0.1_copy.dll_0x180000000"] = dll_entry("C:\\Windows\\System32\\copy.dll", 0x180000000, 64, exports)
        self.assertEqual({}, match_images(dlls, images))
        # too few exports to tell a DLL by them
        few = {1: 0x1100, 2: 0x1110}
        dlls = {"64_10.0.1_small.dll_0x180000000": dll_entry("C:\\Windows\\System32\\small.dll", 0x180000000, 64, few)}
        images = find_dll_images(bytes(0x1000) + build_dll_image("renamed.dll", few, 64), 0)
        self.assertEqual({}, match_images(dlls, images))

    def testScanUsesTheImagesOfTheDump(self):
        exports = {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
        base = 0x20000000
        image_address = base + 0x3000
        sample = page((0x10, image_address + 0x6A50, "<I"), size=0x1000)
        dump = sample + bytes(0x2000) + build_dll_image("KERNELBASE.dll", exports) + bytes(0x1000)
        with tempfile.TemporaryDirectory() as directory:
            db_path = self._db(directory)
            path = os.path.join(directory, "dump.bin")
            with open(path, "wb") as f_dump:
                f_dump.write(dump)
            code, output, errors = run(
                "scan", "--min-confidence", "0", path, "--db", db_path, "--base-addr", hex(base), "--json"
            )
            self.assertEqual(0, code, errors)
            document = json.loads(output)
            self.assertEqual(["Api383"], [api["api"] for api in document["apis"]])
            self.assertEqual(
                [
                    {
                        "api_db": db_path,
                        "dll": "32_10.0.1_KernelBase.dll_0x10000000",
                        "load_address": image_address,
                        "source": SOURCE_IMAGES,
                    }
                ],
                document["placed_dlls"],
            )
            self.assertIn(
                "Placed 1 of 2 DLLs of db.json at their load addresses (1 from the DLL images in the dump)", errors
            )
            # without the image in the dump, the DLL is where the DB has it and the pointer is not found
            with open(path, "wb") as f_dump:
                f_dump.write(dump[:0x3000])
            document = json.loads(
                run("scan", "--min-confidence", "0", path, "--db", db_path, "--base-addr", hex(base), "--json")[1]
            )
            self.assertEqual(([], []), (document["apis"], document["placed_dlls"]))

    def testImagesDoNotMoveADllThatTheDbHasTheLoadAddressOf(self):
        # a DB with the ASLR offsets of its boot has the load address, an image in the dump may be a private copy
        exports = {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
        base, load_address = 0x20000000, 0x30000000
        image_address = base + 0x3000
        sample = page((0x10, image_address + 0x6A50, "<I"), (0x20, load_address + 0x6A80, "<I"), size=0x1000)
        dump = sample + bytes(0x2000) + build_dll_image("KERNELBASE.dll", exports) + bytes(0x1000)
        dlls = {
            "32_10.0.1_KernelBase.dll_0x10000000": dll_entry(
                "C:\\Windows\\SysWOW64\\KernelBase.dll", 0x10000000, 32, exports, load_address
            )
        }
        with tempfile.TemporaryDirectory() as directory:
            db_path = write_db(directory, dlls)
            path = os.path.join(directory, "dump.bin")
            with open(path, "wb") as f_dump:
                f_dump.write(dump)
            arguments = ("scan", "--min-confidence", "0", path, "--db", db_path, "--base-addr", hex(base), "--json")
            code, output, errors = run(*arguments)
            self.assertEqual(0, code, errors)
            document = json.loads(output)
            self.assertEqual((["Api384"], []), ([api["api"] for api in document["apis"]], document["placed_dlls"]))
            # without the offsets, the DB only has the file ImageBase, and the image places the DLL
            code, output, errors = run(*arguments, "--ignore-aslr")
            self.assertEqual(0, code, errors)
            document = json.loads(output)
            self.assertEqual(["Api383"], [api["api"] for api in document["apis"]])
            self.assertEqual([image_address], [placed["load_address"] for placed in document["placed_dlls"]])

    def testTheOwnImageOfTheDumpIsNotLookedAt(self):
        exports = {383: 0x6A50, 384: 0x6A80, 390: 0x7000}
        # a sample that is a DLL with the name and exports of a system DLL, at the start of the dump
        own_image = build_dll_image("KernelBase.dll", exports)
        with tempfile.TemporaryDirectory() as directory:
            db_path = self._db(directory)
            self.assertEqual([], find_dll_images(own_image + bytes(0x1000), 0x20000000))
            path = os.path.join(directory, "dump.bin")
            with open(path, "wb") as f_dump:
                f_dump.write(own_image)
            code, output, errors = run("scan", path, "--db", db_path, "--base-addr", "0x20000000", "--json")
            self.assertEqual([], json.loads(output)["placed_dlls"])
            self.assertNotIn("Placed", errors)

    def testHostileImages(self):
        random_generator = random.Random(7)
        original = bytes(0x1000) + build_dll_image("KernelBase.dll", {383: 0x6A50, 384: 0x6A80}) + bytes(0x1000)
        for _ in range(2000):
            dump = bytearray(original)
            for _ in range(random_generator.randint(1, 6)):
                position = random_generator.choice(
                    [
                        0x1000 + 0x3C,
                        0x1080 + random_generator.randrange(0x80),
                        0x2000 + random_generator.randrange(0x40),
                        0x2100 + random_generator.randrange(0x10),
                        0x2200 + random_generator.randrange(8),
                    ]
                )
                dump[position] = random_generator.choice([0, 0xFF, 0x7F, 0x80, random_generator.randrange(256)])
            find_dll_images(bytes(dump)[: random_generator.randint(0, len(dump))], 0)
        # an export address table of 4 billion entries is cut off by the dump
        crafted = bytearray(original)
        struct.pack_into("<I", crafted, 0x2000 + 20, 0xFFFFFFFF)
        self.assertEqual([], find_dll_images(bytes(crafted), 0))


class PlacementTestSuite(unittest.TestCase):
    """one API DB per Windows build, whatever the boot a dump was taken in"""

    DLLS = {
        # the DB was built in a boot that loaded the DLLs at these addresses
        "64_10.0.1_kernel32.dll_0x180000000": ("C:\\Windows\\System32\\kernel32.dll", 64, 0x7FFC7F260000),
        "64_10.0.1_ntdll.dll_0x180000000": ("C:\\Windows\\System32\\ntdll.dll", 64, 0x7FFC805B0000),
        "64_10.0.1_user32.dll_0x180000000": ("C:\\Windows\\System32\\user32.dll", 64, 0x7FFC7E8C0000),
        "32_10.0.1_kernel32.dll_0x10000000": ("C:\\Windows\\SysWOW64\\kernel32.dll", 32, 0x76480000),
    }
    # the boot of the dump
    NEW_BOOT = {
        "64_10.0.1_kernel32.dll_0x180000000": 0x7FFA12340000,
        "64_10.0.1_ntdll.dll_0x180000000": 0x7FFA55550000,
    }
    API_RVA = {"kernel32.dll": 0xA000, "ntdll.dll": 0x1650, "user32.dll": 0x3100}

    def _db(self, directory):
        dlls = {}
        for key, (path, bitness, old_load) in self.DLLS.items():
            name = path.rsplit("\\", 1)[-1]
            base = 0x180000000 if bitness == 64 else 0x10000000
            dlls[key] = dll_entry(path, base, bitness, {1: self.API_RVA[name], 2: self.API_RVA[name] + 0x20}, old_load)
        return write_db(directory, dlls, os_name="Windows 10 (AMD64)")

    def _memory(self, boot):
        """the pointers of a sample to kernel32!Api1, ntdll!Api1 and user32!Api2, with the DLLs at their addresses in the boot"""
        pointers = [
            (0x100, boot["64_10.0.1_kernel32.dll_0x180000000"] + self.API_RVA["kernel32.dll"]),
            (0x108, boot["64_10.0.1_ntdll.dll_0x180000000"] + self.API_RVA["ntdll.dll"]),
        ]
        return page(*[(offset, value, "<Q") for offset, value in pointers])

    def _modules(self, boot):
        names = {"kernel32.dll": 0, "ntdll.dll": 1}
        return [
            (f"C:\\Windows\\System32\\{name}", boot[key], 0x100000)
            for key in boot
            for name in names
            if f"_{name}_" in key
        ]

    def _moduleFile(self, directory, boot):
        path = os.path.join(directory, "modules.txt")
        with open(path, "w") as f_modules:
            for name, base, _ in self._modules(boot):
                f_modules.write(f"{base:x} {name}\n")
        return path

    def _scan(self, *arguments):
        # every hit, the placement is what is tested here
        code, output, errors = run("scan", *arguments, "--json", "--min-confidence", "0")
        self.assertEqual(0, code, errors)
        return json.loads(output), errors

    def testOtherBootNeedsTheModuleList(self):
        old_boot = {key: load for key, (_, _, load) in self.DLLS.items()}
        with tempfile.TemporaryDirectory() as directory:
            db_path = self._db(directory)
            base = 0x300000
            dump_path = os.path.join(directory, "dump.bin")
            with open(dump_path, "wb") as f_dump:
                f_dump.write(self._memory(self.NEW_BOOT))
            old_dump_path = os.path.join(directory, "old.bin")
            with open(old_dump_path, "wb") as f_dump:
                f_dump.write(self._memory(old_boot))
            # the boot of the DB: found as before, nothing is placed
            document, errors = self._scan(old_dump_path, "--db", db_path, "--base-addr", hex(base))
            self.assertEqual(["Api1", "Api1"], [api["api"] for api in document["apis"]])
            self.assertEqual([], document["placed_dlls"])
            # another boot: the DB does not know the addresses
            document, _ = self._scan(dump_path, "--db", db_path, "--base-addr", hex(base))
            self.assertEqual([], document["apis"])
            modules_path = self._moduleFile(directory, self.NEW_BOOT)
            document, errors = self._scan(
                dump_path, "--db", db_path, "--base-addr", hex(base), "--modules", modules_path
            )
            self.assertEqual(
                [("kernel32.dll", "Api1", 0x100), ("ntdll.dll", "Api1", 0x108)],
                [(api["dll"].split("(")[0], api["api"], api["offset"]) for api in document["apis"]],
            )
            self.assertEqual(
                {(os.path.basename(p["dll"]), p["load_address"], p["source"]) for p in document["placed_dlls"]},
                {
                    ("64_10.0.1_kernel32.dll_0x180000000", 0x7FFA12340000, SOURCE_MODULES),
                    ("64_10.0.1_ntdll.dll_0x180000000", 0x7FFA55550000, SOURCE_MODULES),
                },
            )
            # two DLLs of four are in the list, the others keep the addresses of the DB
            self.assertIn(
                "Warning: Placed 2 of 4 DLLs of db.json at their load addresses (2 from the modules file), 2 keep the addresses of the DB.",
                errors,
            )
            self.assertIn("modules file", errors)
            # the output of the listing is the same, and a missing list is an error
            code, output, _ = run(
                "scan", dump_path, "--db", db_path, "--base-addr", hex(base), "--modules", modules_path
            )
            self.assertEqual(0, code)
            self.assertIn("Api1", output)
            self.assertEqual(1, run("scan", dump_path, "--db", db_path, "--modules", "missing.txt")[0])
            empty_path = os.path.join(directory, "empty.txt")
            open(empty_path, "w").close()
            code, _, errors = run("scan", dump_path, "--db", db_path, "--modules", empty_path)
            self.assertEqual(1, code)
            self.assertIn("no lines", errors)
            code, _, errors = run("scan", dump_path, "--modules", modules_path, "--import-table")
            self.assertEqual(1, code)

    def testMinidumpUsesItsModuleList(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = self._db(directory)
            modules = self._modules(self.NEW_BOOT) + [("C:\\sample.exe", 0x300000, 0x2000)]
            dump = build_minidump([(0x300000, self._memory(self.NEW_BOOT))], modules)
            path = os.path.join(directory, "crash.dmp")
            with open(path, "wb") as f_dump:
                f_dump.write(dump)
            document, errors = self._scan(path, "--db", db_path)
            self.assertEqual([0x300100, 0x300108], [api["offset"] for api in document["apis"]])
            self.assertEqual({SOURCE_MINIDUMP}, {entry["source"] for entry in document["placed_dlls"]})
            self.assertIn("(2 from the minidump module list)", errors)
            # the explicit list comes first: here it moves ntdll.dll away from where the minidump has it
            other = {**self.NEW_BOOT, "64_10.0.1_ntdll.dll_0x180000000": 0x7FFA66660000}
            modules_path = self._moduleFile(directory, other)
            document, errors = self._scan(path, "--db", db_path, "--modules", modules_path)
            self.assertEqual([0x300100], [api["offset"] for api in document["apis"]])
            sources = {entry["dll"][3:].split("_")[1]: entry["source"] for entry in document["placed_dlls"]}
            self.assertEqual({"kernel32.dll": SOURCE_MODULES, "ntdll.dll": SOURCE_MODULES}, sources)

    def testPlacerKeepsTrackOfEverything(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = self._db(directory)
            api_db = read_db(db_path)
            placer = DllPlacer()
            self.assertTrue(placer.isEmpty())
            placer.addModuleList("a", [("system32/kernel32.dll", 0x7FFA12340000)])
            placer.addModuleList(
                "b", [("system32/kernel32.dll", 0x7FFA99990000), ("system32/ntdll.dll", 0x7FFA55550000)]
            )
            placements = placer(api_db, db_path)
            self.assertEqual(
                {
                    "64_10.0.1_kernel32.dll_0x180000000": 0x7FFA12340000,
                    "64_10.0.1_ntdll.dll_0x180000000": 0x7FFA55550000,
                },
                placements,
            )
            self.assertEqual([(db_path, "Windows 10 (AMD64)", 4, {"a": 1, "b": 1})], placer.summaries)
            scout = ApiScout()
            scout.loadDbFile(db_path, lambda db: placements)
            api_map = next(iter(scout.api_maps.values()))
            self.assertEqual("Api1", api_map[0x7FFA12340000 + 0xA000][1])
            self.assertNotIn(0x7FFC7F260000 + 0xA000, api_map)
            # the DLLs that were not placed stay where the DB has them
            self.assertEqual("user32.dll_0x180000000", api_map[0x7FFC7E8C0000 + 0x3100][0])


@unittest.skipUnless(os.path.isfile(WIN11_DB), "the DB of Windows 11 is not there")
class RealDbTestSuite(unittest.TestCase):
    """a DB of the repository (reduced to a few DLLs, to be fast) and a dump of another boot than the one of the DB"""

    NAMES = ("kernel32.dll", "ntdll.dll", "kernelbase.dll")

    def testDumpOfAnotherBoot(self):
        with open(WIN11_DB) as f_db:
            api_db = json.load(f_db)
        dlls = {
            key: dll for key, dll in api_db["dlls"].items() if dll["filepath"].rsplit("\\", 1)[-1].lower() in self.NAMES
        }
        self.assertEqual(6, len(dlls))
        api_db["dlls"] = dlls
        api_db["num_dlls"] = len(dlls)
        shift = 0x2A0000000
        pointers, modules = [], []
        for key, dll in sorted(dlls.items()):
            if dll["bitness"] != 64:
                continue
            old_load = dll["base_address"] - dll["aslr_offset"]
            new_load = old_load + shift
            # an export of a name that no other export of the DLL shares the address with
            addresses = [export["address"] for export in dll["exports"]]
            export = next(
                export
                for export in dll["exports"][len(dll["exports"]) // 2 :]
                if addresses.count(export["address"]) == 1
            )
            pointers.append((new_load + export["address"], key, export["name"]))
            modules.append((dll["filepath"], new_load, 0x200000))
        self.assertEqual(3, len(pointers))
        memory = page(*[(0x40 + 8 * index, address, "<Q") for index, (address, _, _) in enumerate(pointers)])
        with tempfile.TemporaryDirectory() as directory:
            db_path = os.path.join(directory, "win11_part.json")
            with open(db_path, "w") as f_db:
                json.dump(api_db, f_db)
            modules_path = os.path.join(directory, "modules.txt")
            with open(modules_path, "w") as f_modules:
                f_modules.writelines(f"{base:x} {path}\n" for path, base, _ in modules)
            flat_path = os.path.join(directory, "dump_0x00400000")
            with open(flat_path, "wb") as f_dump:
                f_dump.write(memory)
            dmp_path = os.path.join(directory, "crash.dmp")
            with open(dmp_path, "wb") as f_dump:
                f_dump.write(build_minidump([(0x400000, memory)], modules + [("C:\\sample.exe", 0x400000, 0x1000)]))
            expected = sorted(name for _, _, name in pointers)
            for arguments, found in (
                ((flat_path,), []),
                ((flat_path, "--modules", modules_path), expected),
                ((dmp_path,), expected),
                ((dmp_path, "--ignore-aslr"), expected),
            ):
                code, output, errors = run("scan", *arguments, "--db", db_path, "--json")
                self.assertEqual(0, code, errors)
                self.assertEqual(found, sorted(api["api"] for api in json.loads(output)["apis"]), arguments)
            self.assertIn("Placed 3 of 6 DLLs of win11_part.json", errors)
            self.assertIn("3 keep the addresses of the DB", errors)


if __name__ == "__main__":
    unittest.main()
