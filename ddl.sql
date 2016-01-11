DROP SCHEMA public;

CREATE SCHEMA public
  AUTHORIZATION postgres;

CREATE TABLE walk
(
  id    INTEGER PRIMARY KEY     NOT NULL,
  host  INET                    NOT NULL,
  start TIMESTAMP DEFAULT now() NOT NULL,
  stop  TIMESTAMP
);
CREATE TABLE getresponse
(
  id                BIGINT PRIMARY KEY      NOT NULL,
  object_identifier BYTEA                   NOT NULL,
  tag               BYTEA                   NOT NULL,
  value             BYTEA,
  host              INET                    NOT NULL,
  timestamp         TIMESTAMP DEFAULT now() NOT NULL,
  walk              BIGINT,
  CONSTRAINT getresponse_walk_id_fk FOREIGN KEY (walk) REFERENCES walk (id)
);
CREATE INDEX getresponse_object_identifier_index ON getresponse (tag); -- Schema: public


GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;
COMMENT ON SCHEMA public
IS 'standard public schema';

