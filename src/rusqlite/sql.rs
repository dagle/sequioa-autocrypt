pub const ACCOUNTSCHEMA: &str = "CREATE TABLE IF NOT EXISTS autocrypt_account (
    address text primary key not null, 
    key text,
    prefer int,
    enable int
)";

pub const ACCOUNTGET: &str = "SELECT
    address, 
    key, 
    prefer,
    enable
FROM autocrypt_account 
WHERE address = ?";

pub const ACCOUNTINSERT: &str = "INSERT into autocrypt_account (
    address, 
    key,
    prefer,
    enable)
values (?, ?, ?, ?);";

pub const ACCOUNTUPDATE: &str = "UPDATE autocrypt_account SET 
    key = ?,
    prefer = ?,
    enable = ?
WHERE address = ?";

pub const ACCOUNTDELETE: &str = "DELETE FROM autocrypt_account 
    WHERE address = ?;";

pub const PEERSCHEMA: &str = "CREATE TABLE IF NOT EXISTS autocrypt_peer (
    address text not null, 
    last_seen INT8, 
    timestamp INT8,
    key text,
    key_fpr text,
    key_keyid text,
    gossip_timestamp INT8,
    gossip_key text,
    gossip_key_fpr text,
    gossip_key_keyid text,
    prefer int,
    account text,
    FOREIGN KEY(account) REFERENCES account(address),
    PRIMARY KEY(address, account)
)";

pub const PEERINSERT: &str = "INSERT into autocrypt_peer (
    address, 
    last_seen,
    timestamp,
    key,
    key_fpr,
    key_keyid,
    gossip_timestamp,
    gossip_key,
    gossip_key_fpr,
    gossip_key_keyid,
    prefer,
    account)
values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

pub const PEERUPDATE: &str = "UPDATE autocrypt_peer SET 
    last_seen = ?1,
    timestamp = ?2,
    key = ?3,
    key_fpr = ?4,
    key_keyid = ?5,
    gossip_timestamp = ?6,
    gossip_key = ?7,
    gossip_key_fpr = ?8,
    gossip_key_keyid = ?9,
    prefer = ?10,
    account = ?11";

pub const PEERGET: &str = "SELECT
address, 
    last_seen, 
    timestamp, 
    key, 
    gossip_timestamp, 
    gossip_key, 
    prefer,
    account
    FROM autocrypt_peer";
