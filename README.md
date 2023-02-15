# DP_forensics_attackipsid_to_syslog_uid

## Change log

v1.0<br>
11/10/2022 Added conditions for different length attackipsid<br>
11/14/2022 Bugfix for ID where first part of the ID is 6 digits, the second part is 10 digits<br>
11/14/2022 Rebuild the script based on the length of the attackipsid<br>
2/15/2023 Added main_python2.py adapted by by Michael Weinstein(Bloomberg)

## How to run

1. Enter the list of APSolute Vision AttackIpdID into the attackipsid_input.txt

Example

18260860-1663963190<br>
18261280-1663963190<br>
18261282-1663963190<br>
18263671-1663963190<br>
18263894-1663963190<br>
18264724-1663963190<br>
18266413-1663963190<br>
18269552-1663963190<br>
18274579-1663963190<br>

2. Run the script

There are two versions of the script, python3 an python2, you can run either of them depending on the python version installed

python3 main_python3.py

or

python main_python2.py


As an output AttackIpsID will be translated to Syslog ID

Example

AttackIpsID 18260860-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-a37c-0116632e1036<br>
AttackIpsID 18261280-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-a520-0116632e1036<br>
AttackIpsID 18261282-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-a522-0116632e1036<br>
AttackIpsID 18263671-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-ae77-0116632e1036<br>
AttackIpsID 18263894-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-af56-0116632e1036<br>
AttackIpsID 18264724-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-b294-0116632e1036<br>
AttackIpsID 18266413-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-b92d-0116632e1036<br>
AttackIpsID 18269552-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-c570-0116632e1036<br>
AttackIpsID 18274579-1663963190 , syslog ID FFFFFFFF-FFFF-FFFF-d913-0116632e1036<br>
