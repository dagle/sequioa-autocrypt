An autocrypt implementation using sequoia
=========================================

Currently a WIP. 

[Autocrypt](https://autocrypt.org/) is a seamless way of doing encryption. Were
keys are automatically exchanged.

This module uses sequoia and rusqlite (sqlite3) driver by default to track information but could easily support
other engines.

In the autocrypt specification, it's stated that the keys should be locked
but not to bother the user. Because of this, the lib will use a static password
function and it's up to the user to supply it. (IE in config, on asking it on startup etc, or
dynmic on first use).

The store supports wildmode. This means running in single user mode but the user can have multiple account. 
This is useful for people that wants to selfhost a database and have multiple email addresses, each using autocrypt.
This way the database shares all the peers etc.

If it's not obvious, this mode is unsecure if you have more than 1 user, because a user could update other peoples peers
and defeat the encryption of emails. You shouldn't mix and match between modes.
