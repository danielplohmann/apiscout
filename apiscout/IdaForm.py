# -----------------------------------------------------------------------
# based on:
# https://github.com/idapython/src/blob/master/examples/ex_askusingform.py
# (c) Hex-Rays
#
import json
import os

import idautils
import idaapi
if idaapi.IDA_SDK_VERSION < 700:
    from idaapi import Form
    from idaapi import Choose2 as Choose
else:
    from idaapi import Form, Choose

from apiscout.ApiScout import ApiScout


class ApiDbChooser(Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, api_db_folder, flags=0):
        Choose.__init__(self,
                         title,
                         [["Filename", 25], ["OS Version", 20], ["ASLR Offset?", 8], ["DLLs", 6], ["APIs", 6]],
                         embedded=True, width=120, height=10, flags=flags)
        self.row_count = 0
        self.api_db_folder = api_db_folder
        self.items = self.populate(api_db_folder)
        self.icon = 4
        self.selcount = 0

    def populate(self, api_db_folder):
        api_dbs = []
        for filename in os.listdir(api_db_folder):
            if not filename.endswith(".json"):
                continue
            db_data = {}
            with open(api_db_folder + os.sep + filename, "r") as f_api_file:
                db_data = json.loads(f_api_file.read())
            api_dbs.append([filename, db_data["os_version"], "%s" % db_data["aslr_offsets"], "%d" % db_data["num_dlls"], "%d" % db_data["num_apis"]])
            self.row_count += 1
        return api_dbs

    def OnClose(self):
        pass

    def getItems(self, indices):
        items = []
        for index in indices:
            items.append(self.api_db_folder + os.sep + self.items[index][0])
        return items

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

class IdaApiScoutOptionsForm(Form):

    def __init__(self, api_db_folder):
        self.invert = False
        self.chosenValues = []
        self.apiDbChooser = ApiDbChooser("ApiDBs", api_db_folder, flags=Choose.CH_MULTI)
        Form.__init__(self, r"""STARTITEM {id:rNormal}
BUTTON YES* Run
BUTTON CANCEL Cancel
IDA ApiScout

{FormChangeCb}
Please select one or more API DBs from your apiscout/dbs folder:

<Available API DBs:{cApiDbChooser}>

or load a database from another location:

<#Select a file to open#:{iFileOpen}>

<##Ignore ASLR offsets:{rAslr}>{cGroup1}>
""", {
    'iAslrOffset': Form.NumericInput(tp=Form.FT_UINT64, value=0x0),
    'iFileOpen': Form.FileInput(swidth=40, open=True, value="*.*"),
    'cGroup1': Form.ChkGroupControl(("rAslr", "rNormal")),
    'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
    'cApiDbChooser' : Form.EmbeddedChooserControl(self.apiDbChooser)
})

    def OnFormChange(self, fid):
        if fid == self.cApiDbChooser.id:
            indices = self.GetControlValue(self.cApiDbChooser)
            self.chosenValues = self.apiDbChooser.getItems(indices)
        return 1


class ApiChooser(Choose):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, api_results, flags=0):
        Choose.__init__(self,
                         title,
                         [["#", 6], ["Offset", 14], ["API Address", 14], ["DLL", 20], ["API", 35]],
                         embedded=True, width=140, height=20, flags=flags)
        self.row_count = 0
        self.base_address = [ea for ea in idautils.Segments()][0]
        self.scout = ApiScout()
        self.scout.setBaseAddress(self.base_address)
        self.api_results = api_results
        self.all_items = self.populate(api_results)
        self.items = self.populate(api_results)
        self.icon = 4
        self.selcount = 0

    def filterDisplay(self, from_addr, to_addr, distance):
        filtered_items = self.scout.filter(self.api_results, from_addr, to_addr, distance)
        self.items = self.populate(filtered_items)

    def populate(self, api_results):
        api_rows = []
        unified_results = set([])
        for key in api_results:
            unified_results.update(api_results[key])
        for index, entry in enumerate(sorted(unified_results)):
            dll_name = "{} ({}bit)".format(entry[2], entry[4])
            api_rows.append(["%d" % (index + 1), "0x%x" % (self.base_address + entry[0]), "0x%x" % entry[1], dll_name, entry[3]])
            self.row_count += 1
        return api_rows

    def OnClose(self):
        pass

    def getItems(self, l):
        items = []
        for index in l:
            items.append([int(self.items[index][1], 16), int(self.items[index][2], 16), self.items[index][3], str(self.items[index][4])])
        return items

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n


class IdaApiScoutResultsForm(Form):

    def __init__(self, crawled_apis, from_addr=0, to_addr=0):
        self.invert = False
        self.chosenApis = []
        self.apiChooser = ApiChooser("Apis", crawled_apis, flags=Choose.CH_MULTI)
        Form.__init__(self, r"""STARTITEM {id:rNormal}
BUTTON YES* Annotate
BUTTON CANCEL Cancel
IDA ApiScout (Results)

{FormChangeCb}
ApiScout has found the following APIs (select to annotate, e.g. CTRL+A):

<APIs:{cApiChooser}>
{cApiInfo}

Filter APIs by Range -  
<##from  :{iAddrFrom}>
<##to    :{iAddrTo}>
Filter APIs by Grouping - require another API 
<##within:{iByteRange}> bytes
<##Apply Filter:{bApplyFilter}>
""", {
    'cApiInfo': Form.StringLabel("APIs"),
    'bApplyFilter': Form.ButtonInput(self.OnButtonApplyFilter),
    'iAddrFrom': Form.NumericInput(tp=Form.FT_ADDR, value=from_addr),
    'iAddrTo': Form.NumericInput(tp=Form.FT_ADDR, value=to_addr),
    'iByteRange': Form.NumericInput(tp=Form.FT_UINT64, value=0x800),
    'cGroup1': Form.ChkGroupControl(("rFilter", "rNormal")),
    'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
    'cApiChooser' : Form.EmbeddedChooserControl(self.apiChooser)
})

    def OnButtonApplyFilter(self, code=0):
        addr_from = self.GetControlValue(self.iAddrFrom)
        addr_to = self.GetControlValue(self.iAddrTo)
        byte_range = self.GetControlValue(self.iByteRange)
        self.apiChooser.filterDisplay(addr_from, addr_to, byte_range)
        # SetControlValue seems to have broken in some API migration...
        # if addr_from == 0 and addr_to == 0 and byte_range == 0:
        #     self.SetControlValue(self.cApiInfo, "APIs: %d/%d (unfiltered)" % (len(self.apiChooser.items), len(self.apiChooser.all_items)))
        # else:
        #     self.SetControlValue(self.cApiInfo, "APIs: %d/%d (filtered to 0x%x - 0x%x, range: 0x%x)" % (len(self.apiChooser.items), len(self.apiChooser.all_items), addr_from, addr_to, byte_range))
        l = self.GetControlValue(self.cApiChooser)
        self.chosenApis = self.apiChooser.getItems(l)
        self.RefreshField(self.cApiChooser)

    def OnFormChange(self, fid):
        if fid == self.cApiChooser.id:
            l = self.GetControlValue(self.cApiChooser)
            self.chosenApis = self.apiChooser.getItems(l)
        return 1

    def OnClose(self):
        l = self.GetControlValue(self.cApiChooser)
        self.chosenApis = self.apiChooser.getItems(l)
