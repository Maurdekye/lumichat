CREATE TYPE author_type AS ENUM ('User', 'AssistantResponding', 'AssistantFinished');

CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    chat INT NOT NULL,
    author author_type NOT NULL,
    content TEXT NOT NULL,
    created TIMESTAMP NOT NULL,
    FOREIGN KEY (chat) REFERENCES Chats(id)
);
