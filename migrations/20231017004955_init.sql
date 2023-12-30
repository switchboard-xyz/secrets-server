-- Stores the users associated with a given mr_enclave and secret
CREATE TABLE IF NOT EXISTS users
(
    id                  SERIAL                  PRIMARY KEY,
    -- org_id              INT                     NOT NULL,
    user_pubkey         VARCHAR(64)             NOT NULL,
    ciphersuite         VARCHAR(16)             NOT NULL,
    contact_info        TEXT,
    created_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

    UNIQUE(user_pubkey, ciphersuite),
    FOREIGN KEY (org_id) REFERENCES organizations(id)

);

-- Stores the orgs associated with 1+ users
-- CREATE TABLE IF NOT EXISTS organizations
-- (
--     id                  SERIAL                  PRIMARY KEY,
--     org_pubkey          VARCHAR(64)             NOT NULL,
--     ciphersuite         VARCHAR(16)             NOT NULL,
--     created_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
--     updated_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

--     UNIQUE(org_pubkey, ciphersuite)
-- );


-- Stores the secrets associated with a given mr_enclave and user_id
CREATE TABLE IF NOT EXISTS secrets
(
    id                  SERIAL                  PRIMARY KEY,
    user_id             INT                     NOT NULL,
    secret_name         VARCHAR(255)            NOT NULL,
    secret              TEXT                    NOT NULL,
    created_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, secret_name)
);

-- Create an index for better performance
CREATE INDEX idx_secrets_user_id ON secrets(user_id);

-- Stores the mr_enclave values associated with a given user_id
CREATE TABLE IF NOT EXISTS mrenclaves
(
    id                  SERIAL                  PRIMARY KEY,
    user_id             INT                     NOT NULL,
    mr_enclave          VARCHAR(64)             NOT NULL,
    created_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, mr_enclave)
);

-- Create an index for better performance
CREATE INDEX idx_mrenclaves_user_id ON mrenclaves(user_id);

-- Stores the allowable mr_enclave values for a given secret
CREATE TABLE IF NOT EXISTS mrenclaves_whitelist
(
    id                  SERIAL                  PRIMARY KEY,
    mrenclave_id        INT                     NOT NULL,
    secret_id           INT                     NOT NULL,
    created_at          TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

    FOREIGN KEY(mrenclave_id) REFERENCES mrenclaves(id) ON DELETE CASCADE,
    FOREIGN KEY(secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
    UNIQUE(mrenclave_id, secret_id)
);

-- Create indexes for foreign keys
CREATE INDEX idx_mw_mrenclave_id ON mrenclaves_whitelist(mrenclave_id);
CREATE INDEX idx_mw_secret_id ON mrenclaves_whitelist(secret_id);

-- Create or replace the trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

-- Create trigger for the users table
CREATE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Create trigger for the users table
CREATE TRIGGER update_orgs_updated_at
BEFORE UPDATE ON organizations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Create trigger for the secrets table
CREATE TRIGGER update_secrets_updated_at
BEFORE UPDATE ON secrets
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Create trigger for the mrenclaves table
CREATE TRIGGER update_mrenclaves_updated_at
BEFORE UPDATE ON mrenclaves
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Create trigger for the mrenclaves_whitelist table
CREATE TRIGGER update_mrenclaves_whitelist_updated_at
BEFORE UPDATE ON mrenclaves_whitelist
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
