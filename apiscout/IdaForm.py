# -----------------------------------------------------------------------
# based on:
# https://github.com/idapython/src/blob/master/examples/ex_askusingform.py
# (c) Hex-Rays
#
import json
import os
import re

import ida_kernwin
from ida_kernwin import Choose, Form

ICONS = {}


def loadIcon(name):
    """id of an icon shipped in apiscout/data, loaded once per session"""
    if name not in ICONS:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", name + ".png")
        ICONS[name] = ida_kernwin.load_custom_icon(file_name=icon_path, format="png")
    return ICONS[name]


class ApiDbChooser(Choose):
    """the API DBs of a folder, embedded in the options dialog"""

    def __init__(self, title, api_db_folder, flags=0):
        Choose.__init__(
            self,
            title,
            [
                ["File", 29],
                ["Version", 11],
                ["ASLR", 5],
                ["DLLs", 5 | Choose.CHCOL_DEC],
                ["APIs", 7 | Choose.CHCOL_DEC],
            ],
            embedded=True,
            width=150,
            height=8,
            flags=flags,
            icon=loadIcon("icon"),
        )
        self.api_db_folder = api_db_folder
        self.items = self.populate(api_db_folder)

    def populate(self, api_db_folder):
        api_dbs = []
        if not os.path.isdir(api_db_folder):
            return api_dbs
        for filename in sorted(os.listdir(api_db_folder)):
            if not filename.endswith(".json"):
                continue
            try:
                with open(api_db_folder + os.sep + filename) as f_api_file:
                    db_data = json.loads(f_api_file.read())
                api_dbs.append(
                    [
                        filename,
                        str(db_data["os_version"]).split(" ")[0],
                        "yes" if db_data["aslr_offsets"] else "no",
                        str(int(db_data["num_dlls"])),
                        str(int(db_data["num_apis"])),
                    ]
                )
            except (ValueError, KeyError, TypeError):
                continue
        return api_dbs

    def OnClose(self):
        pass

    def getItems(self, indices):
        return [self.api_db_folder + os.sep + self.items[index][0] for index in indices]

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)


class IdaApiScoutOptionsForm(Form):
    def __init__(self, api_db_folder):
        self.chosenValues = []
        self.apiDbChooser = ApiDbChooser("API DBs", api_db_folder, flags=Choose.CH_MULTI)
        Form.__init__(
            self,
            r"""STARTITEM 0
BUTTON YES* Scan
BUTTON CANCEL Cancel
ApiScout

{FormChangeCb}
Select the API DBs of the system the memory dump was taken from (found in apiscout/dbs):
<:{cApiDbChooser}>
<Other API DB file:{iFileOpen}>
<Ignore the ASLR offsets stored in the API DBs:{rAslr}>{cGroup1}>
""",
            {
                "iFileOpen": Form.FileInput(swidth=46, open=True, value=""),
                "cGroup1": Form.ChkGroupControl(("rAslr",)),
                "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                "cApiDbChooser": Form.EmbeddedChooserControl(self.apiDbChooser, swidth=64),
            },
        )

    def OnFormChange(self, fid):
        if fid == self.cApiDbChooser.id:
            indices = self.GetControlValue(self.cApiDbChooser)
            self.chosenValues = self.apiDbChooser.getItems(indices)
        return 1


class ApiResultsChooser(Choose):
    """
    Dockable list of the API references found. Enter or double click jumps to a reference,
    annotation and filtering are offered in the context menu.
    """

    TITLE = "ApiScout"
    ACTION_ANNOTATE = "apiscout:annotate"
    ACTION_ANNOTATE_ALL = "apiscout:annotate_all"
    ACTION_FILTER = "apiscout:filter"

    def __init__(self, tools, rows, rescan):
        Choose.__init__(
            self,
            self.TITLE,
            [
                ["Address", 16 | Choose.CHCOL_EA],
                ["API", 36],
                ["Library", 20],
                ["API Address", 16 | Choose.CHCOL_HEX],
                ["References", 8 | Choose.CHCOL_DEC],
                ["Status", 30],
            ],
            flags=Choose.CH_MULTI | Choose.CH_RESTORE | Choose.CH_CAN_REFRESH,
            icon=loadIcon("icon"),
        )
        self.tools = tools
        self.rescan = rescan
        self.distance = 0
        self._keep_rows = False
        self.all_rows = rows
        self.rows = rows
        self.status = {}
        self.icons = {state: loadIcon("icon_" + state) for state in ("reference", "annotated", "skipped")}

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        row = self.rows[n]
        library = re.sub(r"(_0x[0-9a-fA-F]+)? \(\d+bit\)$", "", row[2])
        return [f"{row[0]:X}", row[3], library, f"{row[1]:X}", str(row[4]), self.status.get(tuple(row[:4]), "")]

    def OnGetEA(self, n):
        return self.rows[n][0]

    def OnGetIcon(self, n):
        state = self.status.get(tuple(self.rows[n][:4]), "reference").split(":")[0].split(" ")[0]
        return self.icons.get(state, self.icons["reference"])

    def OnRefresh(self, selection):
        """the native refresh of the view scans the database again"""
        if self._keep_rows:
            self._keep_rows = False
        else:
            self.all_rows = self.rescan()
            self._applyFilter()
        return [Choose.ALL_CHANGED]

    def _redraw(self):
        # the refresh is carried out later by IDA, OnRefresh() takes the flag back
        self._keep_rows = True
        self.Refresh()

    def OnSelectLine(self, selection):
        if selection:
            ida_kernwin.jumpto(self.rows[selection[0]][0])
        return (Choose.NOTHING_CHANGED,)

    def OnClose(self):
        pass

    def annotate(self, indices):
        self.tools.importTypeLibraries()
        num_renamed, num_skipped, num_xrefs_adapted = self.tools.applyApiNames(
            [self.rows[index] for index in indices], self.status, {row[0] for row in self.all_rows}
        )
        print(f"Annotated {num_renamed} APIs and adapted {num_xrefs_adapted} Xrefs ({num_skipped} skipped).")
        self._redraw()

    def filterByNeighbourhood(self, distance):
        """only show API references with another reference within the given distance, 0 shows all of them"""
        self.distance = distance
        self._applyFilter()
        self._redraw()

    def _applyFilter(self):
        self.rows = self.tools.filterByDistance(self.all_rows, self.distance) if self.distance else self.all_rows

    def show(self):
        if self.Show() < 0:
            return False
        for action_name in ("-", self.ACTION_ANNOTATE, self.ACTION_ANNOTATE_ALL, self.ACTION_FILTER):
            ida_kernwin.attach_action_to_popup(self.GetWidget(), None, action_name)
        return True


class ApiResultsAction(ida_kernwin.action_handler_t):
    """an action of the context menu of the results list"""

    def __init__(self, chooser, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser
        self.callback = callback

    def activate(self, ctx):
        self.callback(self.chooser, list(ctx.chooser_selection))
        return 1

    def update(self, ctx):
        if ctx.widget_title == ApiResultsChooser.TITLE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET
