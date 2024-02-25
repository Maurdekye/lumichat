use std::{cell::RefCell, fmt::Debug, rc::Rc, time::Duration};

use gloo_utils::{format::JsValueSerdeExt, window};
use serde::Serialize;
use shared::{api::me, model::User};
use web_sys::wasm_bindgen::JsValue;
use yew::prelude::*;

use crate::{login::Login, session::Session};

use gloo_timers::future::TimeoutFuture as Timeout;

fn host() -> Option<String> {
    window().location().host().ok()
}

struct JsValuable<T>(T);

impl<T> From<JsValuable<&T>> for JsValue
where
    T: Serialize,
{
    fn from(value: JsValuable<&T>) -> Self {
        JsValue::from_serde(value.0).unwrap()
    }
}

#[allow(unused_macros)]
macro_rules! dbg_log {
    ($($obj:expr),*) => {
        gloo_console::log!($(&web_sys::wasm_bindgen::JsValue::from(crate::JsValuable(&$obj))),*)
    };
}

fn sleep(duration: Duration) -> Timeout {
    Timeout::new(duration.as_millis() as u32)
}

trait DurFrom {
    fn dur_from(self) -> Duration;
}

impl DurFrom for u64 {
    fn dur_from(self) -> Duration {
        Duration::from_secs(self)
    }
}

impl DurFrom for f64 {
    fn dur_from(self) -> Duration {
        Duration::from_secs_f64(self)
    }
}

struct RcRefCell;

impl RcRefCell {
    fn new<T>(value: T) -> Rc<RefCell<T>> {
        Rc::new(RefCell::new(value))
    }
}

macro_rules! wait {
    (1 second) => {
        wait!(1 seconds)
    };
    ($secs:literal seconds) => {
        crate::sleep(crate::DurFrom::dur_from($secs)).await
    };
    ($millis:literal millis) => {
        crate::sleep(std::time::Duration::from_millis($millis)).await
    };
}

macro_rules! get {
    ($route:literal) => {
        get!(@gloo_net::http::Request::get($route).build(), $route)
    };
    ($route:literal, $body:expr) => {
        get!(@gloo_net::http::Request::get($route).json(&$body), $route)
    };
    (@$builder:expr, $route:literal) => {
        $builder
            .unwrap()
            .send()
            .await
            .expect(format!("Unable to get {}", $route).as_str())
    };
}

macro_rules! post {
    ($route:literal) => {
        post!(@gloo_net::http::Request::post($route).build(), $route)
    };
    ($route:literal, $body:expr) => {
        post!(@gloo_net::http::Request::post($route).json(&$body), $route)
    };
    (@$builder:expr, $route:literal) => {
        $builder
            .unwrap()
            .send()
            .await
            .expect(format!("Unable to post {}", $route).as_str())
    };
}

macro_rules! json {
    ($request:expr) => {{
        $request.json().await.expect("Unexpected response")
    }};
}

mod login {

    use serde::Serialize;
    use web_sys::HtmlInputElement;
    use yew::prelude::*;

    use shared::{api::login, model::User};

    #[derive(Serialize)]
    pub enum Msg {
        UpdateIdentifier(String),
        UpdatePassword(String),
        Request,
        Response(login::Response),
        ClearMessage,
        Login(User),
    }

    #[derive(Clone, PartialEq, Properties)]
    pub struct Props {
        pub on_login: Callback<User>,
    }

    #[derive(Clone)]
    pub enum InfoMessage {
        Success(String),
        Progress(String),
        Error(String),
    }

    #[derive(Clone)]
    pub struct Login {
        identifier: String,
        password: String,
        message: Option<InfoMessage>,
    }
    impl Component for Login {
        type Message = Msg;
        type Properties = Props;

        fn create(_ctx: &Context<Self>) -> Self {
            Login {
                identifier: "".to_string(),
                password: "".to_string(),
                message: None,
            }
        }

        fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
            match msg {
                Msg::UpdateIdentifier(identifier) => self.identifier = identifier,
                Msg::UpdatePassword(password) => self.password = password,
                Msg::Request => {
                    let Login {
                        identifier,
                        password,
                        ..
                    } = self.clone();
                    ctx.link().send_future(async {
                        let response: login::Response = json!(post!(
                            "/login",
                            login::Request {
                                identifier,
                                password,
                            }
                        ));
                        Msg::Response(response)
                    });
                    self.message = Some(InfoMessage::Progress("Logging in...".to_string()))
                }
                Msg::Response(login::Response::Failure(failure_reason)) => {
                    let message = match failure_reason {
                        login::FailureReason::AlreadyLoggedIn => "Already logged in!".to_string(),
                        login::FailureReason::InvalidPassword => "Invalid password".to_string(),
                        login::FailureReason::UserDoesNotExist => {
                            format!("User with username/email '{}' not found", self.identifier)
                        }
                    };
                    self.message = Some(InfoMessage::Error(message));
                    ctx.link().send_future(async {
                        wait!(5 seconds);
                        Msg::ClearMessage
                    });
                }
                Msg::Response(login::Response::Success(user)) => {
                    self.message = Some(InfoMessage::Success("Logged in!".to_string()));
                    ctx.link().send_future(async {
                        wait!(500 millis);
                        Msg::Login(user)
                    });
                }
                Msg::ClearMessage => {
                    self.message = None;
                }
                Msg::Login(user) => {
                    ctx.props().on_login.emit(user);
                }
            };
            true
        }

        fn view(&self, ctx: &Context<Self>) -> Html {
            html! {
                <div class={"login"}>
                    <div class={"login-box"}>
                        <div class={"login-form"}>
                            <label for="identifier">{"Username / Email"}</label>
                            <input
                                type="text"
                                id="identifier"
                                value={self.identifier.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input: HtmlInputElement = e.target_unchecked_into();
                                    Msg::UpdateIdentifier(input.value())
                                })}
                            />
                            <label for="password">{"Password"}</label>
                            <input
                                type="password"
                                id="password"
                                value={self.password.clone()}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input: HtmlInputElement = e.target_unchecked_into();
                                    Msg::UpdatePassword(input.value())
                                })}
                                onkeypress={
                                    ctx.link().batch_callback(move |e: KeyboardEvent| {
                                    if e.key() == "Enter" {
                                        e.prevent_default();
                                        return Some(Msg::Request)
                                    }
                                    None
                                })}
                            />
                            <button class="login-button" onclick={ctx.link().callback(|_| Msg::Request)}>{"Login"}</button>
                        </div>
                        {
                            match &self.message {
                                None => html! {},
                                Some(InfoMessage::Success(msg)) =>
                                    html! {
                                        <div class={"login-message success"}>{msg}</div>
                                    },
                                Some(InfoMessage::Progress(msg)) =>
                                    html! {
                                        <div class={"login-message progress"}>{msg}</div>
                                    },
                                Some(InfoMessage::Error(msg)) =>
                                    html! {
                                        <div class={"login-message error"}>{msg}</div>
                                    },
                            }
                        }
                    </div>
                </div>
            }
        }
    }
}

mod session {
    use std::{cell::RefCell, collections::HashMap, fmt::Debug, mem, rc::Rc};

    use futures::stream::SplitSink;
    use futures::StreamExt;
    use gloo_console::{error, log};
    use gloo_net::websocket::futures::WebSocket;
    use shared::{
        api::{chat_message, list_chats, list_messages, new_chat},
        model::{self, AuthorType, ChatId, MessageId, User},
        websocket,
    };
    use web_sys::HtmlInputElement;
    use yew::prelude::*;

    use crate::{host, JsValuable, RcRefCell};

    type ElemKey = u64;

    type WebsocketWriter = SplitSink<WebSocket, gloo_net::websocket::Message>;

    #[derive(Debug)]
    pub enum MessageContent {
        Skeleton { content: String },
        Real(model::Message),
    }

    #[derive(Debug)]
    pub struct Message {
        key: ElemKey,
        inner: MessageContent,
    }

    impl Default for BufferedMessage {
        fn default() -> Self {
            Self {
                content: Default::default(),
                progress: AuthorType::AssistantResponding,
            }
        }
    }

    #[derive(Debug)]
    pub struct LoadedChatMessages {
        message_list: Vec<Rc<RefCell<Message>>>,
        message_index: HashMap<MessageId, Rc<RefCell<Message>>>,
    }

    impl LoadedChatMessages {
        fn new() -> Self {
            Self {
                message_list: Vec::new(),
                message_index: HashMap::new(),
            }
        }

        fn push_message(&mut self, message: model::Message) {
            self.push_message_with_key(message, rand::random());
        }

        fn push_message_with_key(&mut self, message: model::Message, key: ElemKey) {
            let message_id = message.id;
            let message = RcRefCell::new(Message {
                key,
                inner: MessageContent::Real(message),
            });
            self.message_list.push(message.clone());
            self.message_index.insert(message_id, message);
        }
    }

    #[derive(Debug)]
    pub enum ChatMessages {
        Unloaded,
        Loading,
        Loaded(LoadedChatMessages),
    }

    #[derive(Debug)]
    pub struct RealChat {
        chat: model::Chat,
        messages: ChatMessages,
    }

    #[derive(Debug)]
    pub enum ChatContent {
        Skeleton {
            user_message: String,
            user_message_key: ElemKey,
        },
        Real(RealChat),
    }

    #[derive(Debug)]
    pub struct Chat {
        key: ElemKey,
        inner: ChatContent,
    }

    impl Chat {
        pub fn name(&self) -> String {
            match &self.inner {
                ChatContent::Skeleton { .. } => "New Chat".to_string(),
                ChatContent::Real(real_chat) => real_chat.chat.name.to_string(),
            }
        }

        pub fn is_available(&self) -> bool {
            match &self.inner {
                ChatContent::Real(RealChat {
                    messages: ChatMessages::Loaded(loaded_messages),
                    ..
                }) => loaded_messages
                    .message_list
                    .last()
                    .map(|m| match &RefCell::borrow(m).inner {
                        MessageContent::Real(model::Message {
                            author: AuthorType::AssistantFinished,
                            ..
                        }) => true,
                        _ => false,
                    })
                    .unwrap_or(true),
                _ => false,
            }
        }
    }

    #[derive(Debug)]
    pub struct BufferedMessage {
        content: String,
        progress: AuthorType,
    }

    pub struct LoadedChats {
        chat_list: Vec<Rc<RefCell<Chat>>>,
        chat_index: HashMap<ChatId, Rc<RefCell<Chat>>>,
        unknowns_buffer: HashMap<MessageId, BufferedMessage>,
    }

    impl LoadedChats {
        fn new() -> Self {
            Self {
                chat_list: Vec::new(),
                chat_index: HashMap::new(),
                unknowns_buffer: HashMap::new(),
            }
        }
    }

    pub enum Chats {
        Unloaded,
        Loading,
        Loaded(LoadedChats),
    }

    pub enum WebsocketConnection {
        Disconnected,
        Connecting,
        Connected(WebsocketWriter),
    }

    pub struct Session {
        sidebar: bool,
        chats: Chats,
        current_chat: Option<Rc<RefCell<Chat>>>,
        message_input: String,
        websocket: WebsocketConnection,
    }

    pub enum Msg {
        Logout,
        ToggleSidebar,
        NewChat,
        SelectChat(Rc<RefCell<Chat>>),
        UpdateMessage(String),
        SubmitMessage,
        ChatMessageResponse {
            chat: Rc<RefCell<Chat>>,
            response: chat_message::Response,
            user_message_key: ElemKey,
        },
        NewChatResponse {
            response: new_chat::Response,
            chat_key: ElemKey,
            user_message_key: ElemKey,
        },
        LoadChats,
        LoadedChats(list_chats::Response),
        LoadMessages(Rc<RefCell<Chat>>),
        LoadedMessages {
            chat: Rc<RefCell<Chat>>,
            response: list_messages::Response,
        },
        WebsocketTryConnect,
        WebsocketConnected(WebsocketWriter),
        WebsocketData(websocket::Message),
        WebsocketDisconnect,
    }

    impl Debug for Msg {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Logout => write!(f, "Logout"),
                Self::ToggleSidebar => write!(f, "ToggleSidebar"),
                Self::NewChat => write!(f, "NewChat"),
                Self::SelectChat(arg0) => f.debug_tuple("SelectChat").field(arg0).finish(),
                Self::UpdateMessage(arg0) => f.debug_tuple("UpdateMessage").field(arg0).finish(),
                Self::SubmitMessage => write!(f, "SubmitMessage"),
                Self::ChatMessageResponse {
                    chat,
                    response,
                    user_message_key,
                } => f
                    .debug_struct("ChatMessageResponse")
                    .field("chat", chat)
                    .field("response", response)
                    .field("user_message_key", user_message_key)
                    .finish(),
                Self::NewChatResponse {
                    response,
                    chat_key,
                    user_message_key,
                } => f
                    .debug_struct("NewChatResponse")
                    .field("response", response)
                    .field("chat_key", chat_key)
                    .field("user_message_key", user_message_key)
                    .finish(),
                Self::LoadChats => write!(f, "LoadChats"),
                Self::LoadedChats(arg0) => f.debug_tuple("LoadedChats").field(arg0).finish(),
                Self::LoadMessages(arg0) => f.debug_tuple("LoadMessages").field(arg0).finish(),
                Self::LoadedMessages { chat, response } => f
                    .debug_struct("LoadedMessages")
                    .field("chat", chat)
                    .field("response", response)
                    .finish(),
                Self::WebsocketTryConnect => write!(f, "WebsocketTryConnect"),
                Self::WebsocketConnected(_) => f.debug_tuple("WebsocketConnected").finish(),
                Self::WebsocketData(arg0) => f.debug_tuple("WebsocketData").field(arg0).finish(),
                Self::WebsocketDisconnect => write!(f, "WebsocketDisconnect"),
            }
        }
    }

    #[derive(Clone, PartialEq, Properties)]
    pub struct Props {
        pub user: User,
        pub on_logout: Callback<()>,
    }

    impl Component for Session {
        type Message = Msg;
        type Properties = Props;

        fn create(_ctx: &Context<Self>) -> Self {
            Self {
                sidebar: true,
                chats: Chats::Unloaded,
                current_chat: None,
                message_input: String::new(),
                websocket: WebsocketConnection::Disconnected,
            }
        }

        fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
            log!(format!("msg = {msg:#?}"));
            match msg {
                Msg::Logout => {
                    let on_logout = ctx.props().on_logout.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        let response = post!("/logout");
                        assert_eq!(response.status(), 200);
                        on_logout.emit(());
                    });
                }
                Msg::ToggleSidebar => {
                    self.sidebar = !self.sidebar;
                }
                Msg::NewChat => self.current_chat = None,
                Msg::SelectChat(chat) => self.current_chat = Some(chat),
                Msg::UpdateMessage(message) => {
                    self.message_input = message;
                }
                Msg::SubmitMessage => {
                    let content = mem::replace(&mut self.message_input, String::new());
                    match &self.current_chat {
                        Some(chat) => {
                            let user_message_key: ElemKey = rand::random();

                            let ChatContent::Real(real_chat) = &mut RefCell::borrow_mut(chat).inner
                            else {
                                error!("Not allowed to submit a message to a skeleton chat!");
                                return false;
                            };

                            let chat_id = real_chat.chat.id;

                            let ChatMessages::Loaded(loaded_messages) = &mut real_chat.messages
                            else {
                                error!("Messages haven't finished loading yet");
                                return false;
                            };

                            loaded_messages.message_list.push(RcRefCell::new(Message {
                                key: user_message_key,
                                inner: MessageContent::Skeleton {
                                    content: content.clone(),
                                },
                            }));

                            let chat = chat.clone();

                            ctx.link().send_future(async move {
                                let response: chat_message::Response = json!(post!(
                                    "/chat-message",
                                    chat_message::Request {
                                        chat: chat_id,
                                        message: content
                                    }
                                ));

                                Msg::ChatMessageResponse {
                                    chat,
                                    response,
                                    user_message_key,
                                }
                            });
                        }
                        None => {
                            let Chats::Loaded(loaded_chats) = &mut self.chats else {
                                error!("Chats aren't loaded yet");
                                return false;
                            };
                            let chat_key: ElemKey = rand::random();
                            let user_message_key: ElemKey = rand::random();
                            let new_chat_skeleton = RcRefCell::new(Chat {
                                key: chat_key,
                                inner: ChatContent::Skeleton {
                                    user_message: content.clone(),
                                    user_message_key,
                                },
                            });
                            loaded_chats.chat_list.push(new_chat_skeleton.clone());
                            self.current_chat = Some(new_chat_skeleton);
                            ctx.link().send_future(async move {
                                let response: new_chat::Response = json!(post!(
                                    "/new-chat",
                                    new_chat::Request {
                                        initial_message: content
                                    }
                                ));
                                Msg::NewChatResponse {
                                    response,
                                    chat_key,
                                    user_message_key,
                                }
                            });
                        }
                    }
                }
                Msg::ChatMessageResponse {
                    chat,
                    response,
                    user_message_key,
                } => {
                    let Chats::Loaded(loaded_chats) = &mut self.chats else {
                        error!("Recieved new chat message without chats being loaded");
                        return false;
                    };

                    let ChatContent::Real(real_chat) = &mut RefCell::borrow_mut(&chat).inner else {
                        error!("Recieved new chat message for skeleton chat?");
                        return false;
                    };

                    let ChatMessages::Loaded(loaded_messages) = &mut real_chat.messages else {
                        error!("Recieved new chat message for unloaded chat");
                        return false;
                    };

                    let (user_message, mut assistant_response) = match response {
                        chat_message::Response::Failure(reason) => {
                            error!("Chat message failure:", format!("{reason:?}"));
                            return false;
                        }
                        chat_message::Response::Success {
                            user_message,
                            assistant_response,
                        } => (user_message, assistant_response),
                    };

                    loaded_messages.push_message_with_key(user_message, user_message_key);

                    // load buffered tokens that might have been missed
                    if let Some(buffered_message) =
                        loaded_chats.unknowns_buffer.remove(&assistant_response.id)
                    {
                        assistant_response
                            .content
                            .push_str(&buffered_message.content);
                        assistant_response.author = buffered_message.progress;
                    }
                    loaded_messages.push_message(assistant_response);

                    loaded_messages
                        .message_list
                        .retain(|m| matches!(&RefCell::borrow(m).inner, MessageContent::Real(_)));
                }
                Msg::NewChatResponse {
                    response,
                    chat_key,
                    user_message_key,
                } => {
                    let Chats::Loaded(loaded_chats) = &mut self.chats else {
                        error!("Received new chat response message before chats have loaded");
                        return false;
                    };
                    let chat = response.chat;
                    let chat_id = chat.id;
                    let mut loaded_messages = LoadedChatMessages::new();
                    loaded_messages.push_message_with_key(response.user_message, user_message_key);
                    let mut assistant_response = response.assistant_response;

                    // load buffered tokens that might have been missed
                    if let Some(buffered_message) =
                        loaded_chats.unknowns_buffer.remove(&assistant_response.id)
                    {
                        assistant_response
                            .content
                            .push_str(&buffered_message.content);
                        assistant_response.author = buffered_message.progress;
                    }
                    loaded_messages.push_message(assistant_response);
                    let real_chat = RealChat {
                        chat,
                        messages: ChatMessages::Loaded(loaded_messages),
                    };
                    let new_chat = Chat {
                        key: chat_key,
                        inner: ChatContent::Real(real_chat),
                    };
                    let new_chat = RcRefCell::new(new_chat);
                    self.current_chat = Some(new_chat.clone());
                    loaded_chats.chat_list.push(new_chat.clone());
                    loaded_chats.chat_index.insert(chat_id, new_chat.clone());
                    loaded_chats
                        .chat_list
                        .retain(|c| matches!(&RefCell::borrow(c).inner, ChatContent::Real { .. }));
                }
                Msg::LoadChats => {
                    self.chats = Chats::Loading;
                    ctx.link()
                        .send_future(async { Msg::LoadedChats(json!(get!("/list-chats"))) });
                }
                Msg::LoadedChats(response) => {
                    let rc_refcell_chats = response
                        .chats
                        .into_iter()
                        .map(|chat| {
                            (
                                chat.id,
                                RcRefCell::new(Chat {
                                    key: rand::random(),
                                    inner: ChatContent::Real(RealChat {
                                        chat,
                                        messages: ChatMessages::Unloaded,
                                    }),
                                }),
                            )
                        })
                        .collect::<Vec<_>>();
                    let mut loaded_chats = LoadedChats::new();
                    loaded_chats
                        .chat_list
                        .extend(rc_refcell_chats.iter().map(|(_, chat)| chat.clone()));
                    loaded_chats.chat_index.extend(rc_refcell_chats);
                    self.chats = Chats::Loaded(loaded_chats);
                }
                Msg::LoadMessages(chat) => {
                    let chat_id = {
                        let mut chat_borrow = RefCell::borrow_mut(&chat);
                        let ChatContent::Real(real_chat) = &mut chat_borrow.inner else {
                            error!("Can't load messages for a skeleton chat");
                            return false;
                        };
                        real_chat.messages = ChatMessages::Loading;
                        real_chat.chat.id
                    };
                    ctx.link().send_future(async move {
                        let response: list_messages::Response = json!(post!(
                            "/list-messages",
                            list_messages::Request { chat: chat_id }
                        ));
                        Msg::LoadedMessages { chat, response }
                    });
                }
                Msg::LoadedMessages { chat, response } => {
                    let ChatContent::Real(real_chat) = &mut RefCell::borrow_mut(&chat).inner else {
                        unreachable!("Unreachable; can't load messages for a skeleton chat");
                    };
                    let messages = match response {
                        list_messages::Response::Success { messages } => messages,
                        list_messages::Response::Failure(reason) => {
                            error!("Error loading chat messages:", JsValuable(&reason));
                            real_chat.messages = ChatMessages::Unloaded;
                            return false;
                        }
                    };
                    let rc_refcell_messages = messages
                        .into_iter()
                        .map(|message| {
                            (
                                message.id,
                                RcRefCell::new(Message {
                                    key: rand::random(),
                                    inner: MessageContent::Real(message),
                                }),
                            )
                        })
                        .collect::<Vec<_>>();
                    let mut loaded_messages = LoadedChatMessages::new();
                    loaded_messages.message_list.extend(
                        rc_refcell_messages
                            .iter()
                            .map(|(_, message)| message.clone()),
                    );
                    loaded_messages.message_index.extend(rc_refcell_messages);
                    real_chat.messages = ChatMessages::Loaded(loaded_messages);
                }
                Msg::WebsocketTryConnect => {
                    self.websocket = WebsocketConnection::Connecting;
                    let data_callback = ctx.link().callback(Msg::WebsocketData);
                    let close_callback = ctx.link().callback(|_| Msg::WebsocketDisconnect);
                    ctx.link().send_future(async move {
                        let websocket_address =
                            format!("ws://{}/ws", host().expect("Host address not available"));
                        log!("connecting to websocket at", &websocket_address);
                        let websocket = match WebSocket::open(&*websocket_address) {
                            Err(err) => {
                                error!("websocket connection failed:", err.to_string());
                                wait!(1 second);
                                return Msg::WebsocketDisconnect;
                            }
                            Ok(websocket) => websocket,
                        };
                        let (write, mut read) = websocket.split();

                        // respond to arriving websocket messages
                        wasm_bindgen_futures::spawn_local(async move {
                            while let Some(msg) = read.next().await {
                                if let Err(err) = (|| -> Result<_, _> {
                                    let gloo_net::websocket::Message::Text(raw_message) =
                                        msg.map_err(|e| format!("Websocket error: {e}"))?
                                    else {
                                        return Err("Unexpected websocket binary data".to_string());
                                    };
                                    let message: websocket::Message =
                                        serde_json::from_str(&*raw_message)
                                            .map_err(|e| format!("Websocket decode error: {e}"))?;
                                    data_callback.emit(message);
                                    Ok(())
                                })() {
                                    error!(err);
                                }
                            }
                            close_callback.emit(());
                        });

                        Msg::WebsocketConnected(write)
                    });
                }
                Msg::WebsocketConnected(writer) => {
                    log!("websocket connected");
                    self.websocket = WebsocketConnection::Connected(writer);
                }
                Msg::WebsocketData(data) => {
                    dbg_log!("websocket data:", data);
                    match data {
                        websocket::Message::Message {
                            chat: chat_id,
                            message: message_id,
                            content,
                        } => {
                            fn buffer_message(
                                buffer: &mut HashMap<MessageId, BufferedMessage>,
                                message_id: MessageId,
                                content: websocket::chat::Message,
                            ) {
                                let buffered_message = buffer.entry(message_id).or_default();

                                // append tokens to buffer or finalize buffered message
                                match content {
                                    websocket::chat::Message::Token(token) => {
                                        buffered_message.content.push_str(&token)
                                    }
                                    websocket::chat::Message::Finish => {
                                        buffered_message.progress = AuthorType::AssistantFinished
                                    }
                                }
                            }

                            // retrieve inner message referred to in websocket message
                            let Chats::Loaded(loaded_chats) = &mut self.chats else {
                                error!("Received chat update websocket message before chats have loaded");
                                return false;
                            };

                            let Some(chat) = loaded_chats.chat_index.get(&chat_id) else {
                                // chat has not yet been recieved, buffer the in progress message
                                buffer_message(
                                    &mut loaded_chats.unknowns_buffer,
                                    message_id,
                                    content,
                                );
                                return false;
                            };

                            let ChatContent::Real(real_chat) = &mut RefCell::borrow_mut(chat).inner
                            else {
                                error!("Recieved message for skeleton chat", chat_id);
                                return false;
                            };

                            let ChatMessages::Loaded(loaded_messages) = &mut real_chat.messages
                            else {
                                error!("Recieved message for unloaded chat", chat_id);
                                return false;
                            };

                            let Some(message) = loaded_messages.message_index.get(&message_id)
                            else {
                                // message has not yet been recieved, buffer the in progress message
                                buffer_message(
                                    &mut loaded_chats.unknowns_buffer,
                                    message_id,
                                    content,
                                );
                                return false;
                            };

                            let MessageContent::Real(message) =
                                &mut RefCell::borrow_mut(message).inner
                            else {
                                error!("Recieved token for skeleton message", message_id);
                                return false;
                            };

                            // append tokens or finalize message
                            match content {
                                websocket::chat::Message::Token(token) => {
                                    message.content.push_str(&token);
                                }
                                websocket::chat::Message::Finish => {
                                    message.author = AuthorType::AssistantFinished;
                                }
                            }
                        }
                    }
                }
                Msg::WebsocketDisconnect => {
                    log!("websocket connection closed");
                    self.websocket = WebsocketConnection::Disconnected;
                }
            };
            true
        }

        fn view(&self, ctx: &Context<Self>) -> Html {
            // attempt to establish websocket connection
            if matches!(self.websocket, WebsocketConnection::Disconnected) {
                ctx.link().send_message(Msg::WebsocketTryConnect);
            }

            // attempt to load chats
            if matches!(self.chats, Chats::Unloaded) {
                ctx.link().send_message(Msg::LoadChats);
            }

            // attempt to load messages for current chat
            if let Some(chat) = &self.current_chat {
                let chat_borrow = RefCell::borrow(chat);
                if let ChatContent::Real(real_chat) = &chat_borrow.inner {
                    if matches!(real_chat.messages, ChatMessages::Unloaded) {
                        ctx.link().send_message(Msg::LoadMessages(chat.clone()));
                    }
                }
            }

            // render page
            struct MessageDisplay<'a> {
                author: &'a str,
                author_name: String,
                content: String,
                key: ElemKey,
            }

            enum MessagesDisplay<'a> {
                Loaded(Vec<MessageDisplay<'a>>),
                Loading,
            }

            html! {
                <div class="session">
                    <div class={if self.sidebar { "sidebar" } else { "sidebar collapsed" }}>
                        <div class="new-chat">
                            <button onclick={ctx.link().callback(|_| Msg::NewChat)}>{" + New Chat"}</button>
                        </div>
                        <div class="chats-list scrollable">
                            {
                                match &self.chats {
                                    Chats::Loading | Chats::Unloaded => html! {
                                        <div class="loading-chats"></div>
                                    },
                                    Chats::Loaded(loaded_chats) =>
                                    loaded_chats.chat_list.iter().rev().map(|chat| {
                                        let onclick = {
                                            // yes, i know what you're thinking, but both clones are necessary
                                            // the first is so that the callback closure has its own copy
                                            // and the second is so that the closure can give out a unique copy
                                            // each time it's called
                                            let chat = chat.clone();
                                            ctx.link().callback(move |_| Msg::SelectChat(chat.clone()))
                                        };
                                        let chat = RefCell::borrow(chat);
                                        let key = chat.key;
                                        html! {
                                            <div class="chat" {key} {onclick}>{&chat.name()}</div>
                                        }
                                    }).collect::<Html>(),
                                }
                            }
                        </div>
                        <div class="profile">
                            <button onclick={ctx.link().callback(|_| Msg::Logout)}>{"Logout"}</button>
                        </div>
                    </div>
                    <div class="chat-and-sidebar-toggle">
                        <div class="sidebar-toggle">
                            <button onclick={ctx.link().callback(|_| Msg::ToggleSidebar)}>{if self.sidebar { "<" } else { ">" }}</button>
                        </div>
                        <div class="chat-window">
                            <div class="chat-input-container">
                                <textarea class="chat-input"
                                    rows={(self.message_input.chars().filter(|c| *c == '\n').count() + 1).min(24).to_string()}
                                    disabled={self.current_chat.as_ref().is_some_and(|c| !RefCell::borrow(c).is_available())}
                                    oninput={ctx.link().callback(|e: InputEvent| {
                                        let input: HtmlInputElement = e.target_unchecked_into();
                                        Msg::UpdateMessage(input.value())
                                    })}
                                    onkeypress={
                                        let message_input = self.message_input.clone();
                                        ctx.link().batch_callback(move |e: KeyboardEvent| {
                                        if e.key() == "Enter" && !e.shift_key() {
                                            e.prevent_default();
                                            if !message_input.is_empty() {
                                                return Some(Msg::SubmitMessage)
                                            }
                                        }
                                        None
                                    })}
                                    value={self.message_input.clone()}
                                ></textarea>
                            </div>
                            {
                                if let Some(chat) = &self.current_chat {
                                    let chat = RefCell::borrow(chat);
                                    let messages: MessagesDisplay = match &chat.inner {
                                        ChatContent::Skeleton { user_message, user_message_key } => {
                                            MessagesDisplay::Loaded(vec![
                                                MessageDisplay {
                                                    author: "user",
                                                    author_name: ctx.props().user.username.clone(),
                                                    content: user_message.clone(),
                                                    key: *user_message_key,
                                                }
                                            ])
                                        }
                                        ChatContent::Real(real_chat) => {
                                            match &real_chat.messages {
                                                ChatMessages::Loading | ChatMessages::Unloaded => MessagesDisplay::Loading,
                                                ChatMessages::Loaded(loaded_messages) =>
                                                    MessagesDisplay::Loaded(loaded_messages.message_list.iter().map(|message| {
                                                        let message = &*RefCell::borrow(message);
                                                        let key = message.key;
                                                        match &message.inner {
                                                            MessageContent::Skeleton { content } => MessageDisplay {
                                                                author: "user",
                                                                author_name: ctx.props().user.username.clone(),
                                                                content: content.clone(),
                                                                key,
                                                            },
                                                            MessageContent::Real(message) => {
                                                                let (author, author_name) = match message.author {
                                                                    AuthorType::User => ("user", ctx.props().user.username.clone()),
                                                                    AuthorType::AssistantResponding
                                                                    | AuthorType::AssistantFinished => ("assistant", "Assistant".to_string())
                                                                };
                                                                MessageDisplay {
                                                                    author,
                                                                    author_name,
                                                                    content: message.content.clone(),
                                                                    key,
                                                                }
                                                            },
                                                        }
                                                    }).collect::<Vec<_>>()),
                                            }
                                        },
                                    };
                                    html! {
                                        <div key=1 class="chat-messages scrollable">
                                            {
                                                match messages {
                                                    MessagesDisplay::Loaded(messages) => messages.into_iter().map(|MessageDisplay { author, author_name, content, key }| html! {
                                                        <div {key} class={classes!("message-row", author)}>
                                                            <div class="message-author">{author_name}</div>
                                                            <div class="message">{content}</div>
                                                        </div>
                                                    }).collect::<Html>(),
                                                    MessagesDisplay::Loading => html! {
                                                        <div class="loading-messages"></div>
                                                    },
                                                }
                                            }
                                        </div>
                                    }
                                } else {
                                    html! {
                                        <div key=1 class="main-page">
                                            <img class="logo" src="./static/logo.svg"/>
                                            <h2 class="by-line">{"How can I illuminate your day?"}</h2>
                                        </div>
                                    }
                                }
                            }
                        </div>
                    </div>
                </div>
            }
        }
    }
}

#[derive(Debug)]
enum IdentityState {
    Loading,
    Anonymous,
    User(User),
}

#[derive(Debug)]
enum Msg {
    SetIdentity(IdentityState),
}

struct App {
    identity_state: IdentityState,
}

impl Component for App {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        App {
            identity_state: IdentityState::Loading,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::SetIdentity(identity_state) => {
                self.identity_state = identity_state;
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        if let IdentityState::Loading = self.identity_state {
            ctx.link().send_future(async {
                let response: me::Response = json!(get!("/me"));
                match response {
                    me::Response::Anonymous => Msg::SetIdentity(IdentityState::Anonymous),
                    me::Response::User(user) => Msg::SetIdentity(IdentityState::User(user)),
                }
            });
        }
        html! {
            <div class={"app"}>
                {
                    match &self.identity_state {
                        IdentityState::Loading =>
                            html! {
                                <div class={"loading"}></div>
                            },
                        IdentityState::Anonymous => {
                            let on_login = ctx.link().callback(|user| Msg::SetIdentity(IdentityState::User(user)));
                            html! {
                                <Login {on_login} />
                            }
                        },
                        IdentityState::User(user) => {
                            let user = user.clone();
                            let on_logout = ctx.link().callback(|_| Msg::SetIdentity(IdentityState::Anonymous));
                            html! {
                                <Session {user} {on_logout}/>
                            }
                        }

                    }
                }
            </div>
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
