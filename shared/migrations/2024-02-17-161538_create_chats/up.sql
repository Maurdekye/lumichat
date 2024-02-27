CREATE TABLE Chats (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner INT NOT NULL,
    created TIMESTAMP NOT NULL,
    context INT[] NOT NULL DEFAULT '{}',
    model VARCHAR(255) NOT NULL,
    FOREIGN KEY (owner) REFERENCES Users(id)
);
