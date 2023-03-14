extern crate sequoia_openpgp as openpgp;
use rusqlite::types::{FromSql, FromSqlError, ToSqlOutput, Value};
use std::borrow::Cow;
use std::path::Path;

use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{params, Connection, Rows, ToSql};
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::{Serialize, SerializeInto};
use sequoia_openpgp::Cert;

pub mod sql;

use crate::driver::{Selector, SqlDriver};
use crate::{
    account::Account,
    peer::{Peer, Prefer},
    Result,
};
use sql::{
    ACCOUNTGET, ACCOUNTINSERT, ACCOUNTSCHEMA, ACCOUNTUPDATE, PEERGET, PEERINSERT, PEERSCHEMA,
    PEERUPDATE,
};

macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

impl ToSql for Prefer {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(*self as i64)))
    }
}

impl FromSql for Prefer {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let i = i64::column_result(value)?;
        match i {
            0 => Ok(Prefer::Mutual),
            1 => Ok(Prefer::Nopreference),
            x => Err(FromSqlError::OutOfRange(x)),
        }
    }
}

macro_rules! peer_fun {
    ($self:ident, $account:expr, $selector:expr, $($param:expr),+) => {
    {
        if let Some(account_mail) = $account {
            let num = count!($($param)*) + 1;
            let sqlstr = format!("{} WHERE {} and account = ?{};",
                PEERGET, $selector, num);
            let mut selectstmt = $self.conn.prepare(&sqlstr)?;

            let mut rows = selectstmt.query(params![
                $($param),*,
                account_mail,
            ])?;

            Self::row_to_peer(&mut rows)
        } else {
            let sqlstr = format!("{} WHERE {};", PEERGET, $selector);
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
    ($field:expr) => {{
        let unix: Option<i64> = $field?;
        let ts: Option<DateTime<Utc>> = if let Some(unix) = unix {
            let nt = NaiveDateTime::from_timestamp_opt(unix, 0)
                .ok_or_else(|| anyhow::anyhow!("Couldn't parse timestamp"))?;
            let dt = DateTime::<Utc>::from_utc(nt, Utc);
            Some(dt)
        } else {
            None
        };
        ts
    }};
}

pub struct SqliteDriver {
    conn: Connection,
}

impl SqliteDriver {
    pub fn new<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let conn = Connection::open(path)?;
        Ok(SqliteDriver { conn })
    }

    pub fn setup(&self) -> Result<()> {
        // we create all fields even if we
        // don't use prefer and enable
        // unless account-settings is enabled
        // is enabled
        self.conn.execute(ACCOUNTSCHEMA, [])?;

        self.conn.execute(PEERSCHEMA, [])?;
        Ok(())
    }

    fn row_to_peer<'a>(rows: &mut Rows) -> Result<Peer<'a>> {
        if let Some(row) = rows.next()? {
            let mail: String = row.get(0)?;
            let unix: i64 = row.get(1)?;
            let last_seen: DateTime<Utc> = {
                let nt = NaiveDateTime::from_timestamp_opt(unix, 0)
                    .ok_or_else(|| anyhow::anyhow!("Couldn't parse timestamp"))?;
                DateTime::<Utc>::from_utc(nt, Utc)
            };

            let timestamp = get_time!(row.get(2));
            let keystr: Option<String> = row.get(3)?;
            let key: Option<Cow<Cert>> = if let Some(keystr) = keystr {
                CertParser::from_reader(keystr.as_bytes())?
                    .find_map(|cert| cert.ok())
                    .map(Cow::Owned)
            } else {
                None
            };

            let gossip_timestamp = get_time!(row.get(4));
            let gossip_keystr: Option<String> = row.get(5)?;
            let gossip_key: Option<Cow<Cert>> = if let Some(keystr) = gossip_keystr {
                CertParser::from_reader(keystr.as_bytes())?
                    .find_map(|cert| cert.ok())
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
            });
        }
        Err(anyhow::anyhow!("No Peer found"))
    }
}

impl SqlDriver for SqliteDriver {
    fn get_account(&self, canonicalized_mail: &str) -> Result<Account> {
        let mut selectstmt = self.conn.prepare(ACCOUNTGET)?;

        let mut rows = selectstmt.query(params![canonicalized_mail])?;

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
            });
        }
        Err(anyhow::anyhow!("No Account found"))
    }

    fn insert_account(&self, account: &Account) -> Result<()> {
        let output = &mut Vec::new();
        account.cert.as_tsk().armored().serialize(output)?;
        let certstr = std::str::from_utf8(output)?;

        // should we insert the rev cert into the db too?
        self.conn.execute(
            ACCOUNTINSERT,
            params![&account.mail, &certstr, account.prefer, &account.enable,],
        )?;
        Ok(())
    }

    fn update_account(&self, account: &Account) -> Result<()> {
        let output = &mut Vec::new();
        account.cert.as_tsk().armored().serialize(output)?;
        let certstr = std::str::from_utf8(output)?;

        self.conn.execute(
            ACCOUNTUPDATE,
            params![&certstr, account.prefer, &account.enable, &account.mail,],
        )?;
        Ok(())
    }

    fn delete_account(&self, canonicalized_mail: &str, transfer: Option<&str>) -> Result<()> {
        if let Some(transfer) = transfer {
            let peers = "UPDATE autocrypt_peer SET
                account = ?1,
                WHERE account = ?2";
            self.conn
                .execute(peers, params![transfer, canonicalized_mail])?;
        } else {
            let peers = "DELETE FROM autocrypt_peer
                WHERE account = ?";
            self.conn.execute(peers, params![canonicalized_mail])?;
        }

        let accountdelete = "DELETE FROM autocrypt_account 
            WHERE address = ?;";

        self.conn
            .execute(accountdelete, params![&canonicalized_mail])?;
        Ok(())
    }

    fn get_peer(&self, account_mail: Option<&str>, selector: Selector) -> Result<Peer> {
        match selector {
            Selector::Email(mail) => peer_fun!(self, account_mail, "address = ?1", mail),
            Selector::Fpr(fpr) => peer_fun!(
                self,
                account_mail,
                "(key_fpr = ?1 or gossip_key_fpr = ?1)",
                fpr.to_hex()
            ),
            Selector::KeyID(key_id) => peer_fun!(
                self,
                account_mail,
                "(key_keyid = ?1 or gossip_key_keiid = ?1)",
                key_id.to_hex()
            ),
        }
    }

    fn delete_peer(&self, account_mail: Option<&str>, canonicalized_mail: &str) -> Result<()> {
        if let Some(account_mail) = account_mail {
            let accountdelete = "DELETE FROM autocrypt_peer
                WHERE account = ? and address = ?;";
            self.conn
                .execute(accountdelete, params![account_mail, canonicalized_mail])?;
        } else {
            let accountdelete = "DELETE FROM autocrypt_peer
                WHERE address = ?;";
            self.conn
                .execute(accountdelete, params![canonicalized_mail])?;
        }
        Ok(())
    }

    fn insert_peer(&self, peer: &Peer) -> Result<()> {
        let keystr = if let Some(ref key) = peer.cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else {
            None
        };
        let keystr_fpr = peer.cert.as_ref().map(|c| c.fingerprint().to_hex());
        let keystr_id = peer.cert.as_ref().map(|c| c.keyid().to_hex());

        let gossip_keystr = if let Some(ref key) = peer.gossip_cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else {
            None
        };
        let gossip_keystr_fpr = peer.gossip_cert.as_ref().map(|c| c.fingerprint().to_hex());
        let gossip_keystr_id = peer.cert.as_ref().map(|c| c.keyid().to_hex());

        self.conn.execute(
            PEERINSERT,
            params![
                &peer.mail,
                &peer.last_seen.timestamp(),
                &peer.timestamp.map(|t| t.timestamp()),
                &keystr,
                &keystr_fpr,
                &keystr_id,
                &peer.gossip_timestamp.map(|t| t.timestamp()),
                &gossip_keystr,
                &gossip_keystr_fpr,
                &gossip_keystr_id,
                peer.prefer,
                &peer.account,
            ],
        )?;
        Ok(())
    }

    fn update_peer(&self, peer: &Peer, wildmode: bool) -> Result<()> {
        let keystr = if let Some(ref key) = peer.cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else {
            None
        };
        let keystr_fpr = peer.cert.as_ref().map(|c| c.fingerprint().to_hex());
        let keystr_id = peer.cert.as_ref().map(|c| c.keyid().to_hex());

        let gossip_keystr = if let Some(ref key) = peer.gossip_cert {
            Some(String::from_utf8(key.armored().to_vec()?)?)
        } else {
            None
        };
        let gossip_keystr_fpr = peer.gossip_cert.as_ref().map(|c| c.fingerprint().to_hex());
        let gossip_keystr_id = peer.cert.as_ref().map(|c| c.keyid().to_hex());

        // can we do this better?
        let insertstmt = if wildmode {
            format!("{} WHERE address = ?12;", PEERUPDATE)
        } else {
            format!("{} WHERE address = ?12 and account = ?11;", PEERUPDATE)
        };

        self.conn.execute(
            &insertstmt,
            params![
                &peer.last_seen.timestamp(),
                &peer.timestamp.map(|t| t.timestamp()),
                &keystr,
                &keystr_fpr,
                &keystr_id,
                &peer.gossip_timestamp.map(|t| t.timestamp()),
                &gossip_keystr,
                &gossip_keystr_fpr,
                &gossip_keystr_id,
                peer.prefer,
                &peer.account,
                &peer.mail,
            ],
        )?;
        Ok(())
    }
}
