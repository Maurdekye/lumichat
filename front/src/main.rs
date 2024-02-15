use std::time::Duration;

use yew::prelude::*;

use crate::login::Login;

use gloo_timers::future::TimeoutFuture as Timeout;

fn sleep(duration: Duration) -> Timeout {
    Timeout::new(duration.as_millis() as u32)
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

    use shared::login;

    use super::sleep;

    #[derive(Serialize)]
    pub enum Msg {
        UpdateIdentifier(String),
        UpdatePassword(String),
        Request,
        Response(login::Response),
        ClearMessage,
        Reload,
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
        type Properties = ();

        fn create(_ctx: &Context<Self>) -> Self {
            Login {
                identifier: "".to_string(),
                password: "".to_string(),
                message: None,
            }
        }

        fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
            log!("msg:", JsValue::from_serde(&msg).unwrap());
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
                        log!("Sending login request");
                        let response: login::Response = Request::post("/login")
                            .json(&login::Request {
                                identifier,
                                password,
                            })
                            .unwrap()
                            .send()
                            .await
                            .expect("Unable to communicate with server")
                            .json()
                            .await
                            .expect("Unable to decode response");
                        log!("Login response:", JsValue::from_serde(&response).unwrap());
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
                        sleep(Duration::from_secs(5)).await;
                        Msg::ClearMessage
                    });
                }
                Msg::Response(login::Response::Success) => {
                    self.message = Some(InfoMessage::Success("Logged in!".to_string()));
                    ctx.link().send_future(async {
                        sleep(Duration::from_secs(1)).await;
                        Msg::Reload
                    });
                }
                Msg::ClearMessage => {
                    self.message = None;
                }
                Msg::Reload => {}
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

struct App {}

impl Component for App {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        App {}
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <div class={"app"}>
                <Login />
            </div>
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
