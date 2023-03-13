#[cfg(test)]
// [ ] Can we test just verify without without writing shitloads of code?
mod tests {
    use sequoia_autocrypt_store::peer::Peer;
    use sequoia_autocrypt_store::peer::Prefer;
    use sequoia_autocrypt_store::store::AutocryptStore;
    use sequoia_autocrypt_store::driver::SqlDriver;
    use sequoia_autocrypt_store::store::UIRecommendation;
    use sequoia_autocrypt_store_rusqlite::SqliteDriver;
    use sequoia_openpgp::Cert;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::cert::CipherSuite;
    use sequoia_openpgp::crypto::Password;
    use sequoia_openpgp::packet::Signature;
    use sequoia_openpgp::types::KeyFlags;

    use std::str::from_utf8;
    use std::time::SystemTime;
    use chrono::{Duration, Utc};
    // use crate::sqlite::SqliteDriver;

    use sequoia_openpgp::policy::StandardPolicy;


    // use sequoia_autocrypt_store_rusqlite::SqliteDriver;

    type Result<T> = sequoia_openpgp::Result<T>;

    static OUR: &'static str = "art.vandelay@vandelayindustries.com";
    static PEER1: &'static str = "regina.phalange@friends.com";
    static PEER2: &'static str = "ken.adams@friends.com";

    #[derive(PartialEq)]
    enum Mode {
        Seen,
        Gossip,
        _Both, // If we want both seen and gossip (todo)
    }

    fn test_db() -> AutocryptStore<SqliteDriver> {
        let conn = SqliteDriver::new(":memory:").unwrap();
        conn.setup().unwrap();
        AutocryptStore { password: Some(Password::from("hunter2")), conn, wildmode: false}
    }

    fn gen_cert(canonicalized_mail: &str, now: SystemTime) 
        -> Result<(Cert, Signature)> {

        let mut builder = CertBuilder::new();
        builder = builder.add_userid(canonicalized_mail);
        builder = builder.set_creation_time(now);

        builder = builder.set_validity_period(None);

        // builder = builder.set_validity_period(
        //     Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),

        // which one to use?
        // builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        builder = builder.set_cipher_suite(CipherSuite::Cv25519);

        builder = builder.add_subkey(
            KeyFlags::empty()
            .set_transport_encryption(),
            None,
            None,
        );

        builder.generate()
    }

    fn gen_peer(ctx: &AutocryptStore<SqliteDriver>, account_mail: &str, canonicalized_mail: &str,
        mode: Mode, prefer: Prefer) -> Result<()> {
        let now = SystemTime::now();

        let (cert, _) = gen_cert(canonicalized_mail, now)?;

        // Since we don't we don't we don't do as as_tsk() in insert_peer, we won't write the
        // private key
        let peer = Peer::new(canonicalized_mail, account_mail, Utc::now(), 
            &cert, mode == Mode::Gossip, prefer);
        ctx.conn.insert_peer(&peer).unwrap();

        Ok(())
    }

    #[test]
    fn test_gen_key() {
        let ctx = test_db();
        let policy = StandardPolicy::new();

        ctx.update_private_key(&policy, OUR).unwrap();
        let acc = ctx.get_account(OUR).unwrap();

        // check stuff in acc
        ctx.update_private_key(&policy, OUR).unwrap();
        let acc2 = ctx.get_account(OUR).unwrap();

        assert_eq!(acc, acc2);

        // check that PEER1 doesn't return anything
        if let Ok(_) = ctx.get_account(PEER1) {
            assert!(true, "PEER1 shouldn't be in the db!")
        }

        ctx.conn.delete_account(OUR, None).unwrap();
    }

    #[test]
    fn test_gen_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        gen_peer(&ctx, &account.mail, PEER2, Mode::Seen, Prefer::Mutual).unwrap();

        let peer1 = ctx.get_peer(Some(OUR), PEER1).unwrap();
        let peer2 = ctx.get_peer(Some(OUR), PEER2).unwrap();

        assert_eq!(peer1.mail, PEER1);
        assert_eq!(peer2.mail, PEER2);

        assert_ne!(peer1, peer2);
    }

    #[test]
    fn test_update_peer() {
        let policy = StandardPolicy::new();

        let ctx = test_db();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let now = Utc::now();

        let peer1 = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let (cert, _) = gen_cert(PEER1, now.into()).unwrap();

        ctx.update_peer(&account.mail, PEER1, &cert, Prefer::Nopreference, Utc::now(), true).unwrap();

        let updated = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        assert_ne!(peer1, updated);

        ctx.update_peer(&account.mail, PEER1, &cert, Prefer::Nopreference, Utc::now(), false).unwrap();
        let replaced = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        assert_ne!(replaced, updated)
    }

    #[test]
    fn test_update_old_peer_data() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let old_peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let past = Utc::now() - Duration::days(150);
        let (cert, _) = gen_cert(PEER1, past.into()).unwrap();

        ctx.update_peer(&account.mail, PEER1, &cert, Prefer::Nopreference, past, false).unwrap();

        let same_peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();
        assert_eq!(old_peer, same_peer);
    }

    #[test]
    fn test_update_seen() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        let now = SystemTime::now();
        let (cert, _) = gen_cert(PEER1, now).unwrap();

        // Since we don't we don't we don't do as as_tsk() in insert_peer, we won't write the
        // private key
        let now = Utc::now() - Duration::days(1);
        let peer = Peer::new(PEER1, &account.mail, now, 
            &cert, false, Prefer::Mutual);

        ctx.conn.insert_peer(&peer).unwrap();

        // gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let before = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let future = Utc::now();
        ctx.update_last_seen(Some(&account.mail), PEER1, future).unwrap();

        let peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();
        assert_ne!(before.last_seen, peer.last_seen);
    }

    #[test]
    fn test_update_seen_old() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        let peer = ctx.get_peer(Some(&account.mail), PEER1).unwrap();

        let history = Utc::now() - Duration::days(150);

        ctx.update_last_seen(Some(&account.mail), PEER1, history).unwrap();


        assert_ne!(history, peer.last_seen);
    }

    #[test]
    fn test_delete_peer() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        ctx.conn.delete_peer(Some(OUR), PEER1).unwrap();
    }

    #[test]
    fn test_encrypt() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        let input = "This is a small  to test encryption";
        let mut output: Vec<u8> = vec![];
        ctx.encrypt(&policy, OUR, &[PEER1], &mut input.as_bytes(), &mut output).unwrap();
    }

    #[test]
    fn test_decrypt() {
        let ctx = test_db();
        let policy = StandardPolicy::new();

        ctx.update_private_key(&policy, OUR).unwrap();

        let input = "This is a small  to test encryption";

        let mut middle: Vec<u8> = vec![];
        ctx.encrypt(&policy, OUR, &[OUR], &mut input.as_bytes(), &mut middle).unwrap();

        let mut output: Vec<u8> = vec![];
        let mut middle: &[u8] = &middle;

        ctx.decrypt(&policy, OUR, &mut middle, &mut output, None).unwrap();

        let decrypted = from_utf8(&output).unwrap();

        assert_eq!(input, decrypted);
    }

    // #[test]
    // fn test_verify() {
    //     let ctx = test_db();
    //     let policy = StandardPolicy::new();
    //
    //     ctx.update_private_key(&policy, OUR).unwrap();
    //     gen_peer(&ctx, OUR, Mode::Seen, true).unwrap();
    //
    //     let input = "This is a small  to test encryption";
    //
    //     let mut middle: Vec<u8> = vec![];
    //     ctx.encrypt(&policy, OUR, &[PEER1], &mut input.as_bytes(), &mut middle).unwrap();
    //
    //     let mut output: Vec<u8> = vec![];
    //     let mut middle: &[u8] = &middle;
    //
    //     ctx.decrypt(&policy, OUR, &mut middle, &mut output, None).unwrap();
    //
    //     let decrypted = from_utf8(&output).unwrap();
    //
    //     // assert_eq!(input, decrypted);
    // }

    #[test]
    fn test_recommend_available() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();
        assert_eq!(ctx.recommend(Some(OUR), PEER1), UIRecommendation::Available);
    }

    #[test]
    fn test_recommend_disable() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        assert_eq!(ctx.recommend(Some(OUR), PEER1), UIRecommendation::Disable);
        gen_peer(&ctx, &account.mail, PEER1, Mode::Seen, Prefer::Mutual).unwrap();

        assert_eq!(ctx.recommend(Some(OUR), PEER2), UIRecommendation::Disable);
    }

    #[test]
    fn test_recommond_gossip() {
        let ctx = test_db();

        let policy = StandardPolicy::new();
        ctx.update_private_key(&policy, OUR).unwrap();
        let account = ctx.get_account(OUR).unwrap();

        gen_peer(&ctx, &account.mail, PEER1, Mode::Gossip, Prefer::Mutual).unwrap();

        assert_eq!(ctx.recommend(Some(OUR), PEER1), UIRecommendation::Discourage)
    }
}
