########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout, which is licensed under the BSD 2-Clause License,
#  see the file LICENSE of the repository. SPDX-License-Identifier: BSD-2-Clause
#
########################################################################

import shlex
import subprocess
import threading
import traceback


class ThreadedCommand:
    """Enables to run subprocess commands in a different thread with TIMEOUT option.

    Based on jcollado's solution:
    http://stackoverflow.com/questions/1191374/subprocess-with-timeout/4825933#4825933
    """

    command = None
    process = None
    status = None
    output, error = "", ""

    def __init__(self, command):
        if isinstance(command, str):
            command = shlex.split(command)
        self.command = command

    def run(self, timeout=None, **kwargs):
        """Run a command then return: (status, output, error)."""

        def target(**kwargs):
            try:
                self.process = subprocess.Popen(self.command, **kwargs)
                self.output, self.error = self.process.communicate()
                self.status = self.process.returncode
            except Exception:
                self.error = traceback.format_exc()
                self.status = -1

        # default stdout and stderr
        if "stdout" not in kwargs:
            kwargs["stdout"] = subprocess.PIPE
        if "stderr" not in kwargs:
            kwargs["stderr"] = subprocess.PIPE
        # thread
        thread = threading.Thread(target=target, kwargs=kwargs)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self.process.terminate()
            thread.join()
        return {"status": self.status, "std_out": self.output, "std_err": self.error}
