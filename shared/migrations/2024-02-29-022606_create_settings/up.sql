CREATE TABLE Settings (
    scope VARCHAR,
    key VARCHAR,
    value VARCHAR NOT NULL,
    PRIMARY KEY (scope, key)
);