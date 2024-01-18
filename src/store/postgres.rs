use crate::*;

// An example of poem using sqlx to connect to a postgres database
// https://github.com/poem-web/poem/blob/a2e8b98590bec85469f789622e9d62d17cc8a684/examples/openapi/todos/src/main.rs#L12

use poem::error::InternalServerError;
use poem_openapi::Object;
use sqlx::{postgres::PgConnectOptions, query, query_as, Pool, Postgres};

/// User DB schema
#[derive(FromRow, Debug, Object, Clone, Eq, PartialEq)]
pub struct UserPg {
    /// Id
    // #[oai(read_only)]
    // id: i32,
    /// The user's public key
    #[oai(validator(max_length = 64))]
    user_pubkey: String,
    /// The ciphersuite used by the user
    #[oai(validator(max_length = 16))]
    ciphersuite: String,
    /// The contact information of the user
    contact_info: Option<String>,
    /// Timestamp when the user was created
    created_at: DateTime<Utc>,
    /// Timestamp when the user was last updated
    updated_at: DateTime<Utc>,
}

/// Secret DB schema
#[derive(FromRow, Debug, Object, Clone, Eq, PartialEq)]
pub struct SecretPg {
    /// Id
    // #[oai(read_only)]
    // id: i32,
    /// The user id of the secret owner
    user_id: i32,
    /// The name of the secret
    #[oai(validator(max_length = 255))]
    secret_name: String,
    /// The value of the secret
    pub secret: String,
    /// Timestamp when the user was created
    created_at: DateTime<Utc>,
    /// Timestamp when the user was last updated
    updated_at: DateTime<Utc>,
}

/// This struct represents the database schema for MrEnclave. It contains the following fields:
/// * `id`: The unique identifier for the MrEnclave record.
/// * `user_id`: The unique identifier for the user associated with the MrEnclave record.
/// * `mr_enclave`: The value of the MrEnclave record.
/// * `created_at`: The timestamp when the MrEnclave record was created.
/// * `updated_at`: The timestamp when the MrEnclave record was last updated.
#[derive(FromRow, Debug, Object, Clone, Eq, PartialEq)]
pub struct MrEnclave {
    /// Id
    #[oai(read_only)]
    // id: i32,
    // /// User Id
    user_id: i32,
    /// The value of the MrEnclave record
    #[oai(validator(max_length = 64))]
    mr_enclave: String,
    /// Timestamp when the mr_enclave was created
    created_at: DateTime<Utc>,
    /// Timestamp when the mr_enclave was last updated
    updated_at: DateTime<Utc>,
}

/// MrEnclaveWhitelist DB schema
#[derive(FromRow, Debug, Object, Clone, Eq, PartialEq)]
pub struct MrEnclaveWhitelist {
    /// Id
    // #[oai(read_only)]
    // id: i32,
    /// MrEnclave Id
    mrenclave_id: i32,
    /// Secret Id
    secret_id: i32,
    /// Timestamp when the whitelist entry was created
    created_at: DateTime<Utc>,
}

#[derive(FromRow, Debug, Object, Clone, Eq, PartialEq, Serialize)]
pub struct SecretInfoPg {
    pub secret_name: String,
    pub secret: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    pub whitelisted_mrenclaves: Option<Vec<String>>,
}

/// The `PostgresStore` class is a wrapper around the SQL database logic
/// with helper methods for interacting with the database within the
/// poem API handlers.
#[derive(Clone)]
pub struct PostgresStore {
    // TODO: here we can add a cache of secrets to reduce network calls
    // but for security we may want to always fetch the latest data
    pub pool: sqlx::PgPool,
}

impl PostgresStore {
    /// Create a new `PostgresStore` instance.
    pub async fn new(database_url: &str) -> Self {
        let opts: PgConnectOptions = database_url.parse().unwrap();

        // Change the log verbosity level for queries.
        // Information about SQL queries is logged at `DEBUG` level by default.
        // opts.log_statements(log::LevelFilter::Trace);

        let pool = PgPool::connect_with(opts).await.unwrap();
        Self { pool }
    }

    ///////////////////////////////////////////////////////////////////
    /// USER ACTIONS
    ///////////////////////////////////////////////////////////////////
    pub async fn get_user(&self, user_pubkey: &str, ciphersuite: &str) -> Result<UserPg> {
        let user: UserPg = query_as!(
            UserPg,
            r#"
                SELECT user_pubkey, ciphersuite, contact_info, created_at, updated_at FROM users AS u WHERE u.user_pubkey = $1 AND u.ciphersuite = $2;
            "#,
            user_pubkey,
            ciphersuite
        )
            .fetch_one(&self.pool).await
            .map_err(InternalServerError)?;

        return Ok(user);
    }

    pub async fn get_user_secrets(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
    ) -> Result<Vec<SecretPg>> {
        let secrets: Vec<SecretPg> = query_as!(
            SecretPg,
            r#"
                SELECT s.user_id, s.secret_name, s.secret, s.created_at, s.updated_at
                FROM secrets s
                INNER JOIN users u ON s.user_id = u.id
                WHERE u.user_pubkey = $1 AND u.ciphersuite = $2;
            "#,
            user_pubkey,
            ciphersuite
        )
        .fetch_all(&self.pool)
        .await
        .map_err(InternalServerError)?;

        return Ok(secrets);
    }

    pub async fn create_user(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        contact_info: &str,
    ) -> Result<()> {
        info!(
            "inserting (pubkey, ciphersuite, contact info):\n{}\n{}\n{}",
            user_pubkey, ciphersuite, contact_info
        );
        let user: UserPg = query_as!(
            UserPg,
            r#"
                INSERT INTO users (user_pubkey, ciphersuite, contact_info)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_pubkey, ciphersuite) DO UPDATE SET
                    contact_info = excluded.contact_info
                RETURNING user_pubkey, ciphersuite, contact_info, created_at, updated_at
            "#,
            user_pubkey,
            ciphersuite,
            contact_info
        )
        .fetch_one(&self.pool)
        .await
        .map_err(InternalServerError)?;

        Ok(())
    }

    // pub async fn update_user(
    //     &self,
    //     user_pubkey: &str,
    //     ciphersuite: &str,
    //     contact_info: &str,
    // ) -> Result<()> {
    //     sqlx::query!(
    //         r#"
    //         INSERT INTO users (user_pubkey, ciphersuite, contact_info)
    //         VALUES ($1, $2, $3)
    //         ON CONFLICT (user_pubkey)
    //         DO UPDATE SET
    //             ciphersuite = EXCLUDED.ciphersuite,
    //             contact_info = EXCLUDED.contact_info;
    //         "#,
    //         user_pubkey,
    //         ciphersuite,
    //         contact_info
    //     )
    //     .execute(&self.pool)
    //     .await
    //     .map_err(InternalServerError)?;

    //     Ok(())
    // }

    ///////////////////////////////////////////////////////////////////
    /// SECRET ACTIONS
    ///////////////////////////////////////////////////////////////////
    pub async fn create_secret(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        secret_name: &str,
        secret: &str,
    ) -> Result<()> {
        let secret: SecretPg = query_as!(
            SecretPg,
            r#"
                INSERT INTO secrets (user_id, secret_name, secret)
                VALUES (
                    (SELECT id FROM users WHERE user_pubkey = $1 AND ciphersuite = $2), $3, $4
                )
                ON CONFLICT (user_id, secret_name) DO UPDATE SET
                    secret = excluded.secret
                RETURNING user_id, secret_name, secret, created_at, updated_at
            "#,
            user_pubkey,
            ciphersuite,
            secret_name,
            secret
        )
        .fetch_one(&self.pool)
        .await
        .map_err(InternalServerError)?;

        Ok(())
    }

    pub async fn delete_secret(&self, user_pubkey: &str, secret_name: &str) -> Result<()> {
        query!(
            r#"
                DELETE FROM secrets
                WHERE user_id = (SELECT id FROM users WHERE user_pubkey = $1)
                AND secret_name = $2;
            "#,
            user_pubkey,
            secret_name
        )
        .execute(&self.pool)
        .await
        .map_err(InternalServerError)?;

        Ok(())
    }

    pub async fn update_secret(
        &self,
        user_pubkey: &str,
        secret_name: &str,
        new_secret: &str,
    ) -> Result<()> {
        query!(
            r#"
                UPDATE secrets
                SET secret = $3
                WHERE user_id = (SELECT id FROM users WHERE user_pubkey = $1)
                AND secret_name = $2;
            "#,
            user_pubkey,
            secret_name,
            new_secret
        )
        .execute(&self.pool)
        .await
        .map_err(InternalServerError)?;

        Ok(())
    }

    pub async fn get_secrets(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
    ) -> Result<Vec<SecretInfoPg>> {
        let raw_secrets: Vec<SecretInfoPg> = query_as!(
            SecretInfoPg,
            r#"
            SELECT s.secret, s.secret_name, s.created_at, s.updated_at, 
            CASE
              WHEN COUNT(m.mr_enclave) = 0 THEN ARRAY['']
              ELSE ARRAY_AGG(m.mr_enclave)
            END as whitelisted_mrenclaves
            FROM secrets AS s
            INNER JOIN users AS u ON s.user_id = u.id
            LEFT JOIN mrenclaves_whitelist AS mw ON s.id = mw.secret_id
            LEFT JOIN mrenclaves AS m ON mw.mrenclave_id = m.id
            WHERE u.user_pubkey = $1 AND u.ciphersuite = $2
            GROUP BY s.id, s.secret, s.secret_name;
          
                "#,
            user_pubkey,
            ciphersuite
        )
        .fetch_all(&self.pool)
        .await
        .map_err(InternalServerError)?;
        return Ok(raw_secrets);
    }

    /// Return a `Secret` from the database.
    pub async fn get_secret(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        secret_name: &str,
        mr_enclave: &str,
    ) -> Result<Option<String>> {
        // Get all of the secrets for a given user / ciphersuite, and then try to find one with the
        // name `secret_name`
        let secret = self
            .get_secrets(user_pubkey, ciphersuite)
            .await?
            .iter()
            .find(|&x| x.secret_name == secret_name)
            .map(|x| x.clone());

        if secret.is_some() {
            let unwrapped = secret.unwrap();
            if let Some(whitelisted_mrenclaves) = unwrapped.whitelisted_mrenclaves {
                if whitelisted_mrenclaves.contains(&mr_enclave.to_string()) {
                    return Ok(Some(unwrapped.secret));
                }
            }
        }
        Ok(None)
    }

    // Return a list of mapped secret name/value pairings for the specified user & mrEnclave.
    pub async fn get_secrets_map(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        mr_enclave: &str,
    ) -> Result<HashMap<String, String>> {
        // Get all of the secrets for a given user / ciphersuite.
        let raw_secrets = self.get_secrets(user_pubkey, ciphersuite).await?;
        let mut secret_map = HashMap::<String, String>::new();
        raw_secrets.iter().for_each(|secret| {
            // Insert all secrets that are whitelisted for `mr_enclave` into the map.
            if let Some(whitelisted_mrenclaves) = secret.whitelisted_mrenclaves.clone() {
                if whitelisted_mrenclaves.contains(&mr_enclave.to_string()) {
                    secret_map.insert(secret.secret_name.clone(), secret.secret.clone());
                }
            }
        });
        Ok(secret_map)
    }

    ///////////////////////////////////////////////////////////////////
    /// MRENCLAVE ACTIONS
    ///////////////////////////////////////////////////////////////////

    /// Insert a new MrEnclave value into the database for a given user.
    pub async fn create_mrenclave(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        mr_enclave: &str,
    ) -> Result<MrEnclave> {
        let mrenclave: MrEnclave = query_as!(
            MrEnclave,
            r#"
                INSERT INTO mrenclaves (user_id, mr_enclave)
                VALUES (
                    (SELECT id FROM users WHERE user_pubkey = $1 AND ciphersuite = $2), $3
                )
                ON CONFLICT (user_id, mr_enclave) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
                RETURNING user_id, mr_enclave, created_at, updated_at
            "#,
            user_pubkey,
            ciphersuite,
            mr_enclave
        )
        .fetch_one(&self.pool)
        .await
        .map_err(InternalServerError)?;

        Ok(mrenclave)
    }

    pub async fn delete_mrenclave(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        mr_enclave: &str,
    ) -> Result<()> {
        query!(
            r#"
            DELETE FROM mrenclaves 
            WHERE user_id = (SELECT id FROM users WHERE user_pubkey = $1 AND ciphersuite = $2) 
            AND mr_enclave = $3;
            "#,
            user_pubkey,
            ciphersuite,
            mr_enclave
        )
        .fetch_one(&self.pool)
        .await
        .map_err(InternalServerError)?;

        Ok(())
    }

    ///////////////////////////////////////////////////////////////////
    /// MRENCLAVE WHITELIST ACTIONS
    ///////////////////////////////////////////////////////////////////

    /// Insert a new MrEnclave value into the database for a given user.
    pub async fn create_mrenclave_whitelist(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        secret_name: &str,
        mr_enclave: &str,
    ) -> Result<()> {
        let mrenclave_whitelist: MrEnclaveWhitelist = query_as!(
            MrEnclaveWhitelist,
            r#"
                INSERT INTO mrenclaves_whitelist (secret_id, mrenclave_id)
                VALUES (
                    (SELECT id FROM secrets WHERE user_id = (SELECT id FROM users WHERE user_pubkey = $1 AND ciphersuite = $2) AND secret_name = $3),
                    (SELECT id FROM mrenclaves WHERE mr_enclave = $4)
                )
                RETURNING mrenclave_id, secret_id, created_at
            "#,
            user_pubkey,
            ciphersuite,
            secret_name,
            mr_enclave
        )
            .fetch_one(&self.pool).await
            .map_err(InternalServerError)?;

        Ok(())
    }

    pub async fn delete_mrenclave_whitelist(
        &self,
        user_pubkey: &str,
        ciphersuite: &str,
        secret_name: &str,
        mr_enclave: &str,
    ) -> Result<()> {
        query!(
            r#"
                DELETE FROM mrenclaves_whitelist
                WHERE secret_id = (SELECT id FROM secrets WHERE user_id = (SELECT id FROM users WHERE user_pubkey = $1 AND ciphersuite = $2) AND secret_name = $3)
                AND mrenclave_id = (SELECT id FROM mrenclaves WHERE mr_enclave = $4);
            "#,
            user_pubkey,
            ciphersuite,
            secret_name,
            mr_enclave
        )
            .execute(&self.pool).await
            .map_err(InternalServerError)?;

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_crud_operations() {
//         // Replace with your actual database URL
//         let db = PostgresStore::new("your_database_url_here").await;

//         // Insert user
//         let user_id = db
//             .insert_user("pubkey", "ciphersuite", "contact_info")
//             .await
//             .unwrap();
//         assert!(user_id > 0);

//         // Insert secret
//         let secret_id = db
//             .insert_secret("pubkey", "ciphersuite", "secret_name", "secret_value")
//             .await
//             .unwrap();
//         assert!(secret_id > 0);

//         // Get secret
//         let secret = db
//             .get_secret("mr_enclave", "secret_name")
//             .await
//             .unwrap()
//             .unwrap();
//         assert_eq!(secret.value, "secret_value");

//         // Update secret
//         db.update_secret("pubkey", "secret_name", "new_secret_value")
//             .await
//             .unwrap();

//         // Verify the updated secret
//         let updated_secret = db
//             .get_secret("mr_enclave", "secret_name")
//             .await
//             .unwrap()
//             .unwrap();
//         assert_eq!(updated_secret.value, "new_secret_value");

//         // Delete secret
//         db.delete_secret("pubkey", "secret_name").await.unwrap();

//         // Verify deletion
//         let deleted_secret = db.get_secret("mr_enclave", "secret_name").await.unwrap();
//         assert!(deleted_secret.is_none());
//     }
// }

// psql -h 35.224.111.117 -U dev -d secrets
