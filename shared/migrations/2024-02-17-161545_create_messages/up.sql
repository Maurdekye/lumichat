CREATE TYPE author_type AS ENUM ('User', 'Assistant');

CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    chat_id INT NOT NULL,
    author author_type NOT NULL,
    content TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    FOREIGN KEY (chat_id) REFERENCES Chats(id)
);
