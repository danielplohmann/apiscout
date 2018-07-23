ApiScout
========

This project aims at simplifying Windows API import recovery.
As input, arbitrary memory dumps for a known environment can be processed (please note: a reference DB has to be built first, using apiscout/db_builder).
The output is an ordered list of identified Windows API references with some meta information, and an ApiVector fingerprint.

* scout.py -- should give a good outline on how to work with the library.
* ida_scout.py -- is a convenience GUI wrapper for use in IDA Pro.
* match.py -- demonstrates how ApiVectors can be matched against each other and collections of fingerprints.
* collect.py -- builds a database of WinAPI fingerprints (ApiVectors) that can be used for matching.
* export.py -- generates ApiQR diagrams that visualize ApiVectors.

The code should be fully compatible with Python 2 and 3.
There is a blog post describing ApiScout in more detail: http://byte-atlas.blogspot.com/2017/04/apiscout.html.
Also, another blog post explaining how ApiVectors are constructed and stored: https://byte-atlas.blogspot.com/2018/04/apivectors.html.

Version History
---------------

* 2018-07-23: WARNING: Change in Apivector format -- Introduced sorted ApiVectors which are even more space efficient (20%+).
* 2018-06-25: Fixed incompatibility with IDA Pro 7.0+ (THX to @nazywam!)
* 2018-05-23: Added further semantic context groups (THX to Quoscient.io)
* 2018-03-27: Heuristic estimation of Windows API reference counts added
* 2018-03-06: ApiQR visualization of vector results (C-1024)
* 2017-11-28: Added own import table parser to enrich result information
* 2017-08-24: Multi-Segment support in IDA Pro (THX to @nazywam!)
* 2017-05-31: Added Windows 7 SP1 64bit import DB (compatible to Malpedia)

Credits
=======

The idea has previously gone through multiple iterations until reaching this refactored release.
Thanks to Thorsten Jenke and Steffen Enders for their previous endeavours and evaluating a proof-of-concept of this method.
More thanks to Steffen Enders for his work on the visualization of ApiQR diagrams.
Also thanks to Ero Carrera for pefile and Elias Bachaalany for the IDA Python AskUsingForm template. :)


Pull requests welcome! :)
