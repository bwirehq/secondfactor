CREATE TABLE secondfactor_applications (app_id text PRIMARY KEY);
CREATE TABLE secondfactor_factors (
 app_id text NOT NULL REFERENCES secondfactor_applications, subject text NOT NULL,
 secret bytea, version bigint NOT NULL DEFAULT 1 CHECK(version>0), last_verified_time_step bigint NOT NULL DEFAULT -1,
 recovery_pending boolean NOT NULL DEFAULT false, failures int NOT NULL DEFAULT 0,
 failures_since timestamptz NOT NULL DEFAULT now(), blocked_until timestamptz,
 PRIMARY KEY(app_id,subject)
);
CREATE TABLE secondfactor_enrollments (
 app_id text NOT NULL,subject text NOT NULL,secret bytea NOT NULL,session_id text NOT NULL,
 expires_at timestamptz NOT NULL,grant_hash bytea,
 PRIMARY KEY(app_id,subject), FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE
);
CREATE TABLE secondfactor_recovery_codes (
 app_id text NOT NULL,subject text NOT NULL,code_hash bytea NOT NULL,
 PRIMARY KEY(app_id,subject,code_hash),FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE
);
CREATE TABLE secondfactor_proofs (
 app_id text NOT NULL, token_hash bytea NOT NULL,subject text NOT NULL,session_id text NOT NULL,
 version bigint NOT NULL,generation bigint NOT NULL,purpose text NOT NULL CHECK(purpose IN('access','sensitive')),
 created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL,
 PRIMARY KEY(app_id,token_hash),FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE
);
CREATE INDEX ON secondfactor_proofs(app_id,subject,session_id);
CREATE INDEX ON secondfactor_proofs(expires_at);
CREATE TABLE secondfactor_assisted_recoveries (
 app_id text NOT NULL,job_id text NOT NULL,subject text NOT NULL,actor text NOT NULL,reason text NOT NULL,decision_id text NOT NULL,
 state text NOT NULL CHECK(state IN('blocked','invited','replacing','completed','cancelled')),
 pre_generation bigint NOT NULL,new_generation bigint,initiated_at timestamptz NOT NULL DEFAULT now(),
 confirmed_at timestamptz,invitation_hash bytea,expires_at timestamptz,
 PRIMARY KEY(app_id,job_id),FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE
);
CREATE UNIQUE INDEX ON secondfactor_assisted_recoveries(app_id,subject) WHERE state NOT IN('completed','cancelled');
CREATE TABLE secondfactor_recovery_grants (
 app_id text NOT NULL,token_hash bytea NOT NULL,subject text NOT NULL,session_id text NOT NULL,
 version bigint NOT NULL,generation bigint NOT NULL,expires_at timestamptz NOT NULL,
 job_id text,PRIMARY KEY(app_id,token_hash),FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE,
 FOREIGN KEY(app_id,job_id) REFERENCES secondfactor_assisted_recoveries(app_id,job_id)
);
CREATE TABLE secondfactor_rate_limits (app_id text NOT NULL REFERENCES secondfactor_applications,bucket bytea NOT NULL,attempts int NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(app_id,bucket));
CREATE TABLE secondfactor_assertion_replays (app_id text NOT NULL REFERENCES secondfactor_applications,jti text NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(app_id,jti));
CREATE TABLE secondfactor_idempotency (app_id text NOT NULL,subject text NOT NULL,session_id text NOT NULL,operation text NOT NULL,key_hash bytea NOT NULL,request_hash bytea NOT NULL,redacted boolean NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(app_id,subject,session_id,operation,key_hash),FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE);
CREATE TABLE secondfactor_events (
 app_id text NOT NULL,event_id text NOT NULL,subject text NOT NULL,kind text NOT NULL,
 payload jsonb NOT NULL,encrypted_payload bytea,created_at timestamptz NOT NULL DEFAULT now(),
 attempts int NOT NULL DEFAULT 0,lease_hash bytea,lease_until timestamptz,acknowledged_at timestamptz,
 PRIMARY KEY(app_id,event_id),FOREIGN KEY(app_id,subject) REFERENCES secondfactor_factors ON DELETE CASCADE
);
CREATE INDEX ON secondfactor_events(app_id,created_at) WHERE acknowledged_at IS NULL;
