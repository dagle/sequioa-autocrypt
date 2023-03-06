An autocrypt implementation using sequoia
=========================================

Currently a WIP. 

[Autocrypt](https://autocrypt.org/) is a seemless way of doing encryption. Were
keys are automatically exchanged.

This module uses sequoia and sqlite3 database (configureable in the future) to track
additional information.

In the autocrypt specification, it's stated that the keys should be locked
but not to bother the user. Because of this, the lib will use a static password
function and it's up to the user to supply it. (IE in config, on asking it on startup etc, or
dynmic on first use).
