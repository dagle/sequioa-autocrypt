pub const ACCOUNTSCHEMA: &str =
"CREATE TABLE account (
    address text primary key not null, 
    key text,
    prefer int,
    enable int
)";

pub const ACCOUNTSTMT: &str =
"SELECT
    address, 
    key, 
    prefer,
    enable
FROM account 
WHERE address = ?";

pub const ACCOUNTINSERT: &str =
"INSERT or REPLACE into account (
    address, 
    key,
    prefer,
    enable)
values (?, ?, ?, ?);";

pub const PEERSCHEMA: &str = 
"CREATE TABLE peer (
    address text not null, 
    last_seen INT8, 
    timestamp INT8,
    key text,
    key_fpr,
    gossip_timestamp INT8,
    gossip_key text,
    gossip_key_fpr,
    prefer int,
    account text,
    FOREIGN KEY(account) REFERENCES account(address),
    PRIMARY KEY(address, account)
)";

pub const PEERINSERT: &str =
"INSERT or REPLACE into peer (
    address, 
    last_seen,
    timestamp,
    key,
    key_fpr,
    gossip_timestamp,
    gossip_key,
    gossip_key_fpr,
    prefer,
    account)
values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

pub const SEENUPDATE: &str =
"UPDATE peer
SET last_seen = ?1
WHERE address = ?2
AND last_seen < ?1";
// AND account = ?3

pub const PEERSTMT: &str = 
"SELECT
address, 
    last_seen, 
    timestamp, 
    key, 
    gossip_timestamp, 
    gossip_key, 
    prefer,
    account
    FROM peer";
