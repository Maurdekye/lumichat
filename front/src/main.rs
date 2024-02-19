use std::time::Duration;

use gloo_utils::window;
use shared::{me, model::User};
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

    use shared::{login, model::User};

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
    use std::{cell::RefCell, rc::Rc};

    use futures::StreamExt;
    use futures::stream::SplitSink;
    use gloo_console::{error, log};
    use gloo_net::websocket::{futures::WebSocket, Message};
    use shared::{model::User, websocket};
    use web_sys::HtmlInputElement;
    use yew::prelude::*;

    use crate::host;

    type WebsocketWriter = SplitSink<WebSocket, gloo_net::websocket::Message>;

    pub enum Author {
        User,
        Assistant,
    }

    pub struct ChatMessage {
        author: Author,
        content: String,
    }

    pub struct Chat {
        name: String,
        messages: Vec<ChatMessage>,
    }

    pub struct Session {
        sidebar: bool,
        chats: Vec<Rc<RefCell<Chat>>>,
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
        AssistantMessage {
            content: String,
            chat: Rc<RefCell<Chat>>,
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
                chats: Vec::new(),
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
                    let new_message = ChatMessage {
                        author: Author::User,
                        content: self.message_input.clone(),
                    };
                    match &self.current_chat {
                        Some(chat) => chat.borrow_mut().messages.push(new_message),
                        None => {
                            let new_chat = Rc::new(RefCell::new(Chat {
                                name: "New Chat".to_string(),
                                messages: vec![new_message],
                            }));
                            self.chats.push(new_chat.clone());
                            self.current_chat = Some(new_chat);
                        }
                    }
                    self.message_input = String::new();

                    // simulate mock assistant response after delay
                    if let Some(chat) = &mut self.current_chat {
                        let chat = chat.clone();
                        ctx.link().send_future(async {
                            wait!(1 second);
                            Msg::AssistantMessage {
                                content: "Lorum Ipsum Dolor Sit Amet".to_string(),
                                chat,
                            }
                        });
                    }
                }
                Msg::AssistantMessage { content, chat } => {
                    chat.borrow_mut().messages.push(ChatMessage {
                        author: Author::Assistant,
                        content,
                    });
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

                    wasm_bindgen_futures::spawn_local(async move {
                        while let Some(msg) = read.next().await {
                            if let Err(err) = (|| -> Result<_, _> {
                                let Message::Text(raw_message) =
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
                                self.chats.iter().map(|chat| {
                                    let onclick = {
                                        // yes, i know what you're thinking, but both clones are necessary
                                        // the first is so that the callback closure has its own copy
                                        // and the second is so that the closure can give out a unique copy
                                        // each time it's called
                                        let chat = chat.clone();
                                        ctx.link().callback(move |_| Msg::SelectChat(chat.clone()))
                                    };
                                    html! {
                                        <div class="chat" {onclick}><p>{&chat.borrow().name}</p></div>
                                    }
                                }).collect::<Vec<_>>()
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
                                    chat.borrow().messages.iter().map(|message| {
                                        let author = match message.author {
                                            Author::User => "user",
                                            Author::Assistant => "assistant"
                                        };
                                        html! {
                                            <div class={classes!("message-row", author)}>
                                                <div class="message">{&message.content}</div>
                                            </div>
                                        }
                                    }).collect()
                                } else {
                                    Vec::new()
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
