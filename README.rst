ApiScout
========

This project aims at simplifying Windows API import recovery on arbitrary memory dumps.

* scout.py should give a good outline on how to work with the library.
* ida_scout.py is a convenience GUI wrapper for use in IDA Pro.
* match.py demonstrates how WinApi1024 vectors can be matched against each other.
* export.py can be used to generate ApiQR diagrams that visualize WinApi1024 vectors.

Code should be fully compatible with Python 2 and 3.
There is a blog post describing ApiScout in more detail: http://byte-atlas.blogspot.com/2017/04/apiscout.html.
Another blog post explaining how ApiVectors are stored: https://byte-atlas.blogspot.com/2018/04/apivectors.html.

Version History
---------------

* 2018-06-25: Fixed incompatibility with IDA Pro 7.0+ (THX to @nazywam!)
* 2018-05-23: Added further semantic context groups (THX to Quoscient.io)
* 2018-03-27: Heuristic estimation of Windows API reference counts added
* 2018-03-06: ApiQR visualization of vector results (C-1024)
* 2017-11-28: Added own import table parser to enrich result information
* 2017-08-24: Multi-Segment support in IDA Pro (THX to @nazywam!)
* 2017-05-31: Win7 SP1 64bit example import DB (malpedia-compatible)

Credits
=======

The idea has previously gone through multiple iterations until reaching this refactored release.
Thanks to Thorsten Jenke and Steffen Enders for their previous endeavours and evaluating a proof-of-concept of this method.
More thanks to Steffen Enders for his work on the visualization of ApiQR diagrams.
Also thanks to Ero Carrera for pefile and Elias Bachaalany for the IDA Python AskUsingForm template. :)


Pull requests welcome! :)
