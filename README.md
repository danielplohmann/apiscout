# ApiScout

This project aims at simplifying Windows API import recovery.
As input, arbitrary memory dumps for a known environment can be processed (please note: a reference DB has to be built first, using apiscout/db_builder).  
The output is an ordered list of identified Windows API references with some meta information, and an ApiVector fingerprint.  

* scout.py -- should give a good outline on how to work with the library.  
* ida_scout.py -- is a convenience GUI wrapper for use in IDA Pro.  
* match.py -- demonstrates how ApiVectors can be matched against each other and collections of fingerprints.  
* collect.py -- builds a database of WinAPI fingerprints (ApiVectors) that can be used for matching.  
* export.py -- generates ApiQR diagrams that visualize ApiVectors.  
* update.py -- pull the most recent ApiVector DB from Malpedia (requires Malpedia account / API token).  

The code should be fully compatible with Python 2 and 3.  
There is a blog post describing ApiScout in more detail: http://byte-atlas.blogspot.com/2017/04/apiscout.html.  
Also, another blog post explaining how ApiVectors are constructed and stored: https://byte-atlas.blogspot.com/2018/04/apivectors.html.  
We also presented a paper at Botconf 2018 that describes the ApiScout methodology in-depth, including an evaluation over Malpedia: https://journal.cecyf.fr/ojs/index.php/cybin/article/view/20/23  

## Version History

 * 2020-12-09: v1.1.4 - Python3 fixes on DatabaseBuilder (THX to @Dump-GUY!)
 * 2020-07-13: v1.1.3 - Added "install_requires" to setup.py to ensure dependencies are installed.
 * 2020-06-30: v1.1.0 - Now using LIEF for import table parsing. Fixed bug which would not produce ApiVectors when using import table parsing. ApiScout is now also available through PyPI.
 * 2020-03-03: Added a script to pull the most recent ApiVector DB from Malpedia (requires Malpedia account / API token).
 * 2020-03-02: Ported to IDA 7.4 (THX to @jenfrie).
 * 2020-02-18: DB Builder is now compatible up to Python 3.7 (THX to @elanfer).
 * 2019-10-08: Workaround for broken filtering of the API view in IDA 7.3 (THX to @enzok for pointing this out).
 * 2019-08-22: Fixed a bug where missing type info in IDA would lead to a crash (now gives an error message instead).
 * 2019-08-20: Added self-filter to eliminate pointers to own memory image that could be mistakenly treated as API references.
 * 2019-06-06: Added support for proper type reconstruction for annotated APIs in IDA Pro (THX to @FlxP0c)
 * 2019-05-15: Added numpy support for vector calculations (based on implementation provided by @garanews - THX!)
 * 2019-05-15: Fixed a bug in PE mapper where buffer would be shortened because of misinterpretation of section sizes.
 * 2019-01-23: QoL improvements: automated data folder deployment when used as module, logger initialization (THX to @jdval)
 * 2018-08-23: Fixed a bug in PE mapper where the PE header would be overwritten by (empty) section data.
 * 2018-08-21: Added functionality that allows to use import table information instead of crawling for references.
 * 2018-07-31: Fixed convenience functions to create/export vectors from/to lists and dicts, added test coverage.
 * 2018-07-23: WARNING: Change in Apivector format -- Introduced sorted ApiVectors which are even more space efficient (20%+).
 * 2018-06-25: Fixed incompatibility with IDA Pro 7.0+ (THX to @nazywam!)
 * 2018-05-23: Added further semantic context groups (THX to Quoscient.io)
 * 2018-03-27: Heuristic estimation of Windows API reference counts added
 * 2018-03-06: ApiQR visualization of vector results (C-1024)
 * 2017-11-28: Added own import table parser to enrich result information
 * 2017-08-24: Multi-Segment support in IDA Pro (THX to @nazywam!)
 * 2017-05-31: Added Windows 7 SP1 64bit import DB (compatible to Malpedia)

## Credits

The idea has previously gone through multiple iterations until reaching this refactored release.  
Thanks to Thorsten Jenke and Steffen Enders for their previous endeavours and evaluating a proof-of-concept of this method.  
More thanks to Steffen Enders for his work on the visualization of ApiQR diagrams.  
Also thanks to Ero Carrera for pefile and Elias Bachaalany for the IDA Python AskUsingForm template. :)  
Additionally many thanks to Andrea Garavaglia for his performance benchmarks that lead to drastic speedups in the applied matching!  


Pull requests welcome! :)
