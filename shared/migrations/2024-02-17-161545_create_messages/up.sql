CREATE TYPE author_type AS ENUM ('user', 'assistant_responding', 'assistant_finished', 'assistant_error');

CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    chat INT NOT NULL,
    author author_type NOT NULL,
    content TEXT NOT NULL,
    error TEXT,
    created TIMESTAMP NOT NULL,
    FOREIGN KEY (chat) REFERENCES Chats(id)
);
