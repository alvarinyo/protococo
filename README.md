``protococo`` helps you design, test and debug custom binary protocols
======================================================================

Protococo is:
- A simple, clean, and human-readable file format that lets you design binary protocol specifications: cocofile
- A command line utility that helps you debug and test your binary protocols specified in cocofiles


This is an example of a cocofile specification for a simple foo protocol:

```
[general_message]
02          #STX
FF          #FF FIELD
XX          #MESSAGE TYPE
XXXXXXXX    #BODY LENGTH, lengthof BODY, encodedas bigendian
N           #BODY
03          #ETX

[foo_message]
#subtypeof general_message
#override MESSAGE TYPE
01          #FOO MESSAGE
#override MESSAGE BODY
XX          #FOO FIELD A
XXXX        #FOO FIELD B
N           #FOO DATA

[bar_message]
#subtypeof general_message
#override MESSAGE TYPE
02          #BAR MESSAGE
#override MESSAGE BODY
XX          #BAR FIELD A
N           #BAR DATA
```

The protococo.py cli tool is able to parse that cocofile and use it to check message correctness (protococo.py check), identify the name of an input message (protococo.py find), or create sample messages following the specification (create).
