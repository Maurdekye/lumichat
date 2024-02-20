# Flow 1: new chat message created

1. empty chat
2. user types message in and hits enter
    message send box is disabled for that chat
    loading icon for pending assistant response is created
    client sends initial message to server for new chat (/new-chat)
3. server recieves new chat request with new message
    creates new chat with message
    creates empty assistant response in database and prepares to send new request
    responds with verification that new chat was created, as well as returning empty assistant response
    has an `unrecieved` flag attached to it, to let the user know that its not fully recieved yet
4. client recieves confirmation from api call
    keeps chat input for that chat disabled, since "unreceived" flag is set on most recent chat message
    appends new empty loading chat message
5. server establishes connection to assistant api
6. server begins sending response chat fragments over to client once api starts responding (Message { content: Token })
    contains the chat & message id of the assistant message with the chat fragments
    stores the chat fragemnts in a buffer that get added to the ongoing chat in a local message buffer
7. client begins adding new chat fragments to the incoming chat message
8. server recieves finalizing token
    sends message finalizer to the client (Message { content: Finish })
    stores the full message in the database and clears the buffer
    sets the `unreceived` flag off for the message to denote it was fully received
    begins title creation process
    once title is received, sets the new chat's title to that title
    sends a final webhook event to update that chat's title on the client
9. client recieves chat finalization
    unlocks the chat input 

Api:
* /new-chat { initial_message: String }

Websocket:
* Message {
    message: MessageId,
    content: {
        Token: {
            token: String
        },
        Finish,
    }
}

# Flow 2: Chat message continuation

1. chat with existing user-bot response
2. user types message in and hits enter
    message send box is disabled for that chat
    loading icon for pending assistant response is created
3. server recieves new message for existing chat
    creates new message in the chat
    creates empty assistant response in database and prepares to send new request
... flow continues the same from flow 1

Api:
* /chat-message { chat: ChatId, message: String }

# Flow 3: Listing all chats

1. user loads a new session
2. client makes a request to list all recent chats in the server
3. server receives the request
    queries the database to get a list of all chats for the user, without messages attached
    responds with message list 
4. user clicks a chat in the sidebar to select
4a. if the chat is in an unloaded state, the client fetches the message list from the server
4b. if the chat is in a loaded state, the client checks the id of the most recent message against the server to check if it needs to get updated chat text
    if it's out of date, then it fetches a fresh list of chat messages from the server
    client stores the chat messages as part of the chat
5. client displays the messages in order

Api:
* /list-chats {}
* /check-chat { chat: ChatId }
* /list-messages { chat: ChatId }