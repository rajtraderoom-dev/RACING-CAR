BEGIN;
ALTER TABLE devices ADD COLUMN hardware_verified boolean NOT NULL DEFAULT false;
CREATE TABLE refresh_token_history(hash text PRIMARY KEY,session_id uuid NOT NULL REFERENCES sessions(id),used_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE audit_heads(department_key text PRIMARY KEY,last_hash text NOT NULL);
INSERT INTO schema_migrations VALUES(2);
COMMIT;
