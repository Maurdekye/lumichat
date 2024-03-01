CREATE TABLE ModelSettings (
    scope VARCHAR PRIMARY KEY,
    temperature FLOAT NOT NULL,
    context_length INT NOT NULL,
    system_prompt TEXT
);