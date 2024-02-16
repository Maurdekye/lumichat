use std::time::Duration;

use gloo_console::log;
use gloo_net::http::Request;
use shared::{me, model::User};
use yew::prelude::*;

use crate::{login::Login, session::Session};

use gloo_timers::future::TimeoutFuture as Timeout;

fn sleep(duration: Duration) -> Timeout {
    Timeout::new(duration.as_millis() as u32)
}

macro_rules! wait {
    ($secs:literal seconds) => {
        sleep(Duration::from_secs($secs)).await
    };
    ($millis:literal millis) => {
        sleep(Duration::from_millis($millis)).await
    };
}

macro_rules! get {
    ($route:literal) => {
        get!(@Request::get($route).build(), $route)
    };
    ($route:literal, $body:expr) => {
        get!(@Request::get($route).json(&$body), $route)
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
        post!(@Request::post($route).build(), $route)
    };
    ($route:literal, $body:expr) => {
        post!(@Request::post($route).json(&$body), $route)
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

    extern crate wasm_bindgen_futures as futures;

    use std::time::Duration;

    use futures::wasm_bindgen::JsValue;
    use gloo_console::log;
    use gloo_net::http::Request;
    use gloo_utils::format::JsValueSerdeExt;
    use serde::Serialize;
    use web_sys::HtmlInputElement;
    use yew::prelude::*;

    use shared::{login, model::User};

    use super::sleep;

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
                    log!("Logging in user", JsValue::from_serde(&user).unwrap());
                    ctx.props().on_login.emit(user);
                }
            };
            true
        }

        fn view(&self, ctx: &Context<Self>) -> Html {
            html! {
                <div class={"login-container"}>
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
    use gloo_net::http::Request;
    use shared::model::User;
    use yew::prelude::*;

    pub struct Session {}

    pub enum Msg {
        Logout,
    }

    #[derive(Clone, PartialEq, Properties)]
    pub struct Props {
        pub user: User,
        pub on_logout: Callback<()>,
    }

    impl Component for Session {
        type Message = Msg;
        type Properties = Props;

        fn create(_ctx: &yew::prelude::Context<Self>) -> Self {
            Self {}
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
            };
            true
        }

        fn view(&self, ctx: &yew::prelude::Context<Self>) -> yew::prelude::Html {
            html! {
                <div>
                    <div>{format!("Hello {}!", &ctx.props().user.username)}</div>
                    <button onclick={ctx.link().callback(|_| Msg::Logout)}>{"Logout"}</button>
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
        log!("app message:", format!("{msg:#?}"));
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
