# v3.0.1

Fixed:
 - Security issue: an attacker specifying a large "p2c" value can cause
   JSONWebEncryption.Decrypt and JSONWebEncryption.DecryptMulti to consume large
   amounts of CPU, causing a DoS.
