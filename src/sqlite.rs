extern crate sequoia_openpgp as openpgp;
use std::borrow::Cow;
use std::path::PathBuf;

use chrono::{DateTime, Utc, NaiveDateTime};
use rusqlite::{Connection, params, Rows};
use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::{Serialize, SerializeInto};

use crate::driver::SqlDriver;
use crate::peer::Prefer;
use crate::sql::PEERSTMT;
use crate::{Result, peer::Peer, account::Account};

static DBNAME: &str = "autocrypt.db";

pub fn setup(con: &Connection) -> Result<()> {
    // we create all fields even if we
    // don't use prefer and enable 
    // unless account-settings is enabled
    // is enabled
    let accountschema =
        "CREATE TABLE account (
            address text primary key not null, 
            key text,
            prefer int,
            enable int
            )";
    con.execute(accountschema, [])?;

    // should a peer be connect with an Account?
    let peerschema = 
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

    con.execute(peerschema, [])?;
    Ok(())
}

// macro_rules! peerstmt {
//     ($($selector:expr),*) => {
//         concat!("SELECT
//             address, 
//             last_seen, 
//             timestamp, 
//             key, 
//             gossip_timestamp, 
//             gossip_key, 
//             prefer,
//             account
//             FROM peer
//             ", $selector,*)
//     };
// }

macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

macro_rules! peer_fun {
    ($self:ident, $account:expr, $selector:expr, $($param:expr),+) => {
    {
        if let Some(account_mail) = $account {
            let num = count!($($param)*) + 1;
            let sqlstr = format!("{} WHERE {} and account = ?{};",
                PEERSTMT, $selector, num);
            let mut selectstmt = $self.conn.prepare(&sqlstr)?;

            let mut rows = selectstmt.query(params![
                $($param),*,
                account_mail,
            ])?;

            Self::row_to_peer(&mut rows)
        } else {
            let sqlstr = format!("{} WHERE {};", PEERSTMT, $selector);
            let mut selectstmt = $self.conn.prepare(&sqlstr)?;
            let mut rows = selectstmt.query(params![
                $($param),*
            ])?;
            Self::row_to_peer(&mut rows)
        }
    }
    };
}

macro_rules! get_time {
    ($field:expr) => {
        {
            let unix: Option<i64> = $field?;
            let ts: Option<DateTime<Utc>> = if let Some(unix) = unix {
                let nt = NaiveDateTime::from_timestamp_opt(unix, 0).ok_or_else(||
                    anyhow::anyhow!(
                        "Couldn't parse timestamp")
                )?;
                let dt = DateTime::<Utc>::from_utc(nt, Utc);
                Some(dt)
            } else {
                None
            };
            ts
        }
    }
}

pub struct SqliteDriver {
    pub conn: Connection,
}

impl SqliteDriver {
    pub fn new(path: &str) -> Result<Self> {
        let mut dbpath = PathBuf::new();
        dbpath.push(path);
        dbpath.push(DBNAME);
        let con = Connection::open(dbpath)?;
        Ok(SqliteDriver { conn: con })
    }

    fn row_to_peer<'a>(rows: &mut Rows) -> Result<Peer<'a>> {
        if let Some(row) = rows.next()? {
            let mail: String = row.get(0)?;
            let unix: i64 = row.get(1)?;
            let last_seen: DateTime<Utc> = {
                let nt = NaiveDateTime::from_timestamp_opt(unix, 0).ok_or_else(||
                    anyhow::anyhow!(
                        "Couldn't parse timestamp")
                )?;
                DateTime::<Utc>::from_utc(nt, Utc)
            };

            let timestamp = get_time!(row.get(2));
            let keystr: Option<String> = row.get(3)?;
            let key: Option<Cow<Cert>> = if let Some(keystr) = keystr {
                CertParser::from_reader(keystr.as_bytes())?.find_map(|cert| cert.ok())
                .map(Cow::Owned)
            } else {
                None
            };

            let gossip_timestamp = get_time!(row.get(4));
            let gossip_keystr: Option<String> = row.get(5)?;
            let gossip_key: Option<Cow<Cert>> = if let Some(keystr) = gossip_keystr {
                CertParser::from_reader(keystr.as_bytes())?.find_map(|cert| cert.ok())
                .map(Cow::Owned)
            } else {
                None
            };
            let prefer: Prefer = row.get(6)?;
            let account: String = row.get(7)?;

            return Ok(Peer {
                mail,
                account,
                last_seen,
                timestamp,
                cert: key,
                gossip_timestamp,
                gossip_cert: gossip_key,
                prefer,
            })
        }
        return Err(anyhow::anyhow!("No Peer found"));
    }
}

impl SqlDriver for SqliteDriver {
    fn get_account(&self, canonicalized_mail: &str) -> Result<Account> {
        let mut selectstmt = self.conn.prepare(
            "SELECT
            address, 
            key, 
            prefer,
            enable
            FROM account 
            WHERE address = ?")?;

        let mut rows = selectstmt.query(params![
            canonicalized_mail
        ])?;

        if let Some(row) = rows.next()? {
            let mail: String = row.get(0)?;
            let keystr: String = row.get(1)?;
            // move to convert
            let cert: Cert = CertParser::from_reader(keystr.as_bytes())?
                .find_map(|cert| cert.ok())
                .ok_or(anyhow::anyhow!("No valid key found for account"))?;

            let prefer: Prefer = row.get(2)?;
            let enable: bool = row.get(3)?;

            return Ok(Account {
                mail,
                cert,
                prefer,
                enable,
            })
        }
        return Err(anyhow::anyhow!("No Account found"));
    }

    // fn insert_account(&self, canonicalized_mail: &str, &cert: openpgp::Cert) -> Result<()> {
    //     let account = Account { 
    //         mail: canonicalized_mail.to_owned(), cert, prefer: Prefer::Nopreference, enable: false };
    //     self.update_account(&account)
    // }

    fn update_account(&self, account: &Account) -> Result<()> {
        let output = &mut Vec::new();
        account.cert.as_tsk().armored().serialize(output)?;
        let certstr = std::str::from_utf8(output)?;
        // should we insert the rev cert into the db too?
        let accountstmt = 
            "INSERT or REPLACE into account (
                address, 
                key,
                prefer,
                enable)
            values (?, ?, ?, ?);";
        self.conn.execute(accountstmt, params![
            &account.mail, 
            &certstr,
            // todo

            &account.prefer,
            &account.enable,
        ])?;
        Ok(())
    }

    fn delete_account(&self, account: &Account) -> Result<()> {
        let accountdelete = 
            "DELETE FROM account 
            WHERE account = ?;";

        self.conn.execute(accountdelete, params![&account.mail])?;
        Ok(())
    }

    fn get_peer(&self, account_mail: Option<&str>, selector: crate::driver::Selector) -> Result<Peer> {

        match selector {
            crate::driver::Selector::Email(mail) =>
                peer_fun!(self, account_mail, "address = ?1", mail), 
            crate::driver::Selector::Fpr(fpr) => 
                peer_fun!(self, account_mail, "(key_fpr = ?1 or gossip_key_fpr = ?1)",
                fpr.to_hex()),
            crate::driver::Selector::KeyID(key_id) => 
                peer_fun!(self, account_mail, "(key_keyid = ?1 or gossip_key_keiid = ?1)",
                key_id.to_hex())
        }
    }

    fn delete_peer(&self, peer: &Peer) -> Result<()> {
        let accountdelete = 
            "DELETE FROM account
            WHERE account = ?;";
        // self.con.execute(accountdelete, params![&account.mail])?;
        Ok(())
    }

    fn insert_peer(&self, peer: &Peer) -> Result<()> {
        let keystr = if let Some(ref key) = peer.cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else { None };
        let keystr_fpr = peer.cert.as_ref().map(|c| c.fingerprint().to_hex());

        let gossip_keystr = if let Some(ref key) = peer.gossip_cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else { None};
        let gossip_keystr_fpr = peer.gossip_cert.as_ref().map(|c| c.fingerprint().to_hex());

        let insertstmt = 
            "INSERT into peer (
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
        self.conn.execute(insertstmt, params![
            &peer.mail, 
            &peer.last_seen.timestamp(),
            &peer.timestamp.map(|t| t.timestamp()),
            &keystr,
            &keystr_fpr,
            &peer.gossip_timestamp.map(|t| t.timestamp()),
            &gossip_keystr,
            &gossip_keystr_fpr,
            &peer.prefer,
            &peer.account,
        ])?;
        Ok(())
    }

    fn update_peer(&self, peer: &Peer, wildmode: bool) -> Result<()> {
        let keystr = if let Some(ref key) = peer.cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else { None };
        let keystr_fpr = peer.cert.as_ref().map(|c| c.fingerprint().to_hex());

        let gossip_keystr = if let Some(ref key) = peer.gossip_cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else { None};
        let gossip_keystr_fpr = peer.gossip_cert.as_ref().map(|c| c.fingerprint().to_hex());

        // can we do this better?
        let insertstmt = if wildmode {
            "UPDATE peer SET 
                last_seen = ?1,
                timestamp = ?2,
                key = ?3,
                key_fpr = ?4,
                gossip_timestamp = ?5,
                gossip_key = ?6,
                gossip_key_fpr = ?7,
                prefer = ?8,
                account = ?9
            WHERE address = ?10 and account = ?9"
        } else {
            "UPDATE peer SET 
                last_seen = ?1,
                timestamp = ?2,
                key = ?3,
                key_fpr = ?4,
                gossip_timestamp = ?5,
                gossip_key = ?6,
                gossip_key_fpr = ?7,
                prefer = ?8,
                account = ?9
            WHERE address = ?10"
        };
        self.conn.execute(insertstmt, params![
            &peer.last_seen.timestamp(),
            &peer.timestamp.map(|t| t.timestamp()),
            &keystr,
            &keystr_fpr,
            &peer.gossip_timestamp.map(|t| t.timestamp()),
            &gossip_keystr,
            &gossip_keystr_fpr,
            &peer.prefer,
            &peer.account,

            &peer.mail, 
        ])?;
        Ok(())
    }
}