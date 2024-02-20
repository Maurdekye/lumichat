use std::{cell::RefCell, rc::Rc, time::Duration};

use gloo_utils::window;
use shared::{api::me, model::User};
use yew::prelude::*;

use crate::{login::Login, session::Session};

use gloo_timers::future::TimeoutFuture as Timeout;

fn host() -> Option<String> {
    window().location().host().ok()
}

#[allow(unused_macros)]
macro_rules! dbg_log {
    ($($msg:literal, $obj:expr),*) => {
        gloo_console::log!($($msg, <wasm_bindgen_futures::wasm_bindgen::JsValue as gloo_utils::format::JsValueSerdeExt>::from_serde(&$obj).unwrap()),*)
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
                            />
                            <button onclick={ctx.link().callback(|_| Msg::Request)}>{"Login"}</button>
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
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    use futures::stream::SplitSink;
    use futures::StreamExt;
    use gloo_console::{error, log};
    use gloo_net::websocket::futures::WebSocket;
    use shared::{
        api::{chat_message, new_chat},
        model::{self, AuthorType, ChatId, MessageId, User},
        websocket,
    };
    use web_sys::HtmlInputElement;
    use yew::prelude::*;

    use crate::{host, RcRefCell};

    type ElemKey = u64;

    fn push_message(
        message_list: &mut Vec<Rc<RefCell<Message>>>,
        message_index: &mut HashMap<MessageId, Rc<RefCell<Message>>>,
        message: model::Message,
        key: ElemKey,
    ) {
        let message_id = message.id;
        let message = RcRefCell::new(Message {
            key,
            inner: MessageInner::Real(message),
        });
        message_list.push(message.clone());
        message_index.insert(message_id, message);
    }

    type WebsocketWriter = SplitSink<WebSocket, gloo_net::websocket::Message>;

    pub enum MessageInner {
        Skeleton { content: String },
        Real(model::Message),
    }

    pub struct Message {
        key: ElemKey,
        inner: MessageInner,
    }

    pub enum ChatInner {
        Skeleton {
            user_message: String,
            user_message_key: ElemKey,
        },
        Real {
            chat: model::Chat,
            message_list: Vec<Rc<RefCell<Message>>>,
            message_index: HashMap<MessageId, Rc<RefCell<Message>>>,
        },
    }

    pub struct Chat {
        key: ElemKey,
        inner: ChatInner,
    }

    impl Chat {
        pub fn name(&self) -> String {
            match &self.inner {
                ChatInner::Skeleton { .. } => "New Chat".to_string(),
                ChatInner::Real { chat, .. } => chat.name.to_string(),
            }
        }

        pub fn is_available(&self) -> bool {
            match &self.inner {
                ChatInner::Skeleton { .. } => false,
                ChatInner::Real { message_list, .. } => message_list
                    .last()
                    .map(|m| match &RefCell::borrow(m).inner {
                        MessageInner::Real(model::Message {
                            author: AuthorType::AssistantFinished,
                            ..
                        }) => true,
                        _ => false,
                    })
                    .unwrap_or(true),
            }
        }
    }

    pub struct Session {
        sidebar: bool,
        chat_list: Vec<Rc<RefCell<Chat>>>,
        chat_index: HashMap<ChatId, Rc<RefCell<Chat>>>,
        current_chat: Option<Rc<RefCell<Chat>>>,
        message_input: String,
        websocket: Option<WebsocketWriter>,
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
        WebsocketConnect(WebsocketWriter),
        WebsocketData(websocket::Message),
        WebsocketDisconnect,
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
                chat_list: Vec::new(),
                chat_index: HashMap::new(),
                current_chat: None,
                message_input: String::new(),
                websocket: None,
            }
        }

        fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
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
                    let content = self.message_input.clone();
                    match &self.current_chat {
                        Some(chat) => {
                            let user_message_key: ElemKey = rand::random();
                            let chat_id = match &mut chat.borrow_mut().inner {
                                ChatInner::Skeleton { .. } => {
                                    error!("Not allowed to submit a message to a skeleton chat!");
                                    return false;
                                }
                                ChatInner::Real {
                                    chat, message_list, ..
                                } => {
                                    message_list.push(RcRefCell::new(Message {
                                        key: user_message_key,
                                        inner: MessageInner::Skeleton {
                                            content: content.clone(),
                                        },
                                    }));
                                    chat.id
                                }
                            };
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
                            let chat_key: ElemKey = rand::random();
                            let user_message_key: ElemKey = rand::random();
                            let new_chat_skeleton = RcRefCell::new(Chat {
                                key: chat_key,
                                inner: ChatInner::Skeleton {
                                    user_message: content.clone(),
                                    user_message_key,
                                },
                            });
                            self.chat_list.push(new_chat_skeleton.clone());
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
                    self.message_input = String::new();
                }
                Msg::ChatMessageResponse {
                    chat,
                    response,
                    user_message_key,
                } => {
                    if let ChatInner::Real {
                        message_list,
                        message_index,
                        ..
                    } = &mut chat.borrow_mut().inner
                    {
                        match response {
                            chat_message::Response::Success {
                                user_message,
                                assistant_response,
                            } => {
                                push_message(
                                    message_list,
                                    message_index,
                                    user_message,
                                    user_message_key,
                                );
                                let assistant_message_key: ElemKey = rand::random();
                                push_message(
                                    message_list,
                                    message_index,
                                    assistant_response,
                                    assistant_message_key,
                                );
                            }
                            chat_message::Response::Failure(reason) => {
                                error!("Chat message failure:", format!("{reason:?}"));
                            }
                        };
                        message_list
                            .retain(|m| matches!(&RefCell::borrow(m).inner, MessageInner::Real(_)));
                    } else {
                        error!("Recieved new chat message for skeleton chat?");
                    };
                }
                Msg::NewChatResponse {
                    response,
                    chat_key,
                    user_message_key,
                } => {
                    let chat = response.chat;
                    let chat_id = chat.id;
                    let mut message_list = Vec::new();
                    let mut message_index = HashMap::new();
                    push_message(
                        &mut message_list,
                        &mut message_index,
                        response.user_message,
                        user_message_key,
                    );
                    let assistant_message_key: ElemKey = rand::random();
                    push_message(
                        &mut message_list,
                        &mut message_index,
                        response.assistant_response,
                        assistant_message_key,
                    );
                    let new_chat = Chat {
                        key: chat_key,
                        inner: ChatInner::Real {
                            chat,
                            message_list,
                            message_index,
                        },
                    };
                    let new_chat = RcRefCell::new(new_chat);
                    self.current_chat = Some(new_chat.clone());
                    self.chat_list.push(new_chat.clone());
                    self.chat_index.insert(chat_id, new_chat.clone());
                    self.chat_list
                        .retain(|c| matches!(&RefCell::borrow(c).inner, ChatInner::Real { .. }));
                }
                Msg::WebsocketConnect(writer) => {
                    log!("websocket connected");
                    self.websocket = Some(writer);
                }
                Msg::WebsocketData(data) => {
                    log!("websocket data:", format!("{data:#?}"));
                }
                Msg::WebsocketDisconnect => {
                    log!("websocket connection closed");
                    self.websocket = None;
                }
            };
            true
        }

        fn view(&self, ctx: &Context<Self>) -> Html {
            // attempt to establish websocket connection
            if self.websocket.is_none() {
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

                    Msg::WebsocketConnect(write)
                })
            }

            html! {
                <div class="session">
                    <div class={if self.sidebar { "sidebar" } else { "sidebar collapsed" }}>
                        <div class="profile">
                            <button onclick={ctx.link().callback(|_| Msg::Logout)}>{"Logout"}</button>
                        </div>
                        <div class="chats-list">
                            {
                                for self.chat_list.iter().map(|chat| {
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
                                        <div class="chat" {key} {onclick}><p>{&chat.name()}</p></div>
                                    }
                                })
                            }
                            <div class="new-chat">
                                <button onclick={ctx.link().callback(|_| Msg::NewChat)}>{" + New Chat"}</button>
                            </div>
                        </div>
                    </div>
                    <div class="sidebar-toggle">
                        <button onclick={ctx.link().callback(|_| Msg::ToggleSidebar)}>{if self.sidebar { "<" } else { ">" }}</button>
                    </div>
                    <div class="chat-window">
                        <div class="chat-input-container">
                            <input class="chat-input"
                                disabled={self.current_chat.as_ref().is_some_and(|c| !RefCell::borrow(c).is_available())}
                                oninput={ctx.link().callback(|e: InputEvent| {
                                    let input: HtmlInputElement = e.target_unchecked_into();
                                    Msg::UpdateMessage(input.value())
                                })}
                                onkeypress={
                                    let message_input = self.message_input.clone();
                                    ctx.link().batch_callback(move |e: KeyboardEvent| {
                                    if e.key() == "Enter" {
                                        e.prevent_default();
                                        if !message_input.is_empty() {
                                            return Some(Msg::SubmitMessage)
                                        }
                                    }
                                    None
                                })}
                                value={self.message_input.clone()}
                            />
                        </div>
                        <div class="chat-messages">
                            {
                                if let Some(chat) = &self.current_chat {
                                    let chat = RefCell::borrow(chat);
                                    let messages = match &chat.inner {
                                        ChatInner::Skeleton { user_message, user_message_key } => {
                                            vec![
                                                ("user", user_message.clone(), *user_message_key)
                                            ]
                                        }
                                        ChatInner::Real { message_list, .. } => {
                                            message_list.iter().map(|message| {
                                                let message = &*RefCell::borrow(message);
                                                let key = message.key;
                                                match &message.inner {
                                                    MessageInner::Skeleton { content } => ("user", content.clone(), key),
                                                    MessageInner::Real(message) => {
                                                        let author = match message.author {
                                                            AuthorType::User => "user",
                                                            AuthorType::AssistantResponding
                                                            | AuthorType::AssistantFinished => "assistant"
                                                        };
                                                        (author, message.content.clone(), key)
                                                    },
                                                }
                                            })
                                        }.collect::<Vec<_>>(),
                                    };
                                    messages.into_iter().map(|(author, message, key)| html! {
                                        <div {key} class={classes!("message-row", author)}>
                                            <div class="message">{message}</div>
                                        </div>
                                    }).collect::<Html>()
                                } else {
                                    html! { <></> }
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
                                <div class={"loading"}>{"Loading..."}</div>
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
