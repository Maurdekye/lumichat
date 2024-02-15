use yew::prelude::*;

use crate::login::Login;

mod login {

    extern crate wasm_bindgen_futures as futures;

    use futures::wasm_bindgen::JsValue;
    use gloo_console::log;
    use gloo_net::http::Request;
    use gloo_utils::format::JsValueSerdeExt;
    use serde::Serialize;
    use web_sys::HtmlInputElement;
    use yew::prelude::*;

    use shared::login;

    #[derive(Serialize)]
    pub enum Msg {
        UpdateIdentifier(String),
        UpdatePassword(String),
        Login,
    }

    #[derive(Clone)]
    pub struct Login {
        identifier: String,
        password: String,
    }

    impl Component for Login {
        type Message = Msg;
        type Properties = ();

        fn create(_ctx: &Context<Self>) -> Self {
            Login {
                identifier: "".to_string(),
                password: "".to_string(),
            }
        }

        fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
            log!("msg:", JsValue::from_serde(&msg).unwrap());
            match msg {
                Msg::UpdateIdentifier(identifier) => self.identifier = identifier,
                Msg::UpdatePassword(password) => self.password = password,
                Msg::Login => {
                    let Login {
                        identifier,
                        password,
                    } = self.clone();
                    futures::spawn_local(async move {
                        let body = JsValue::from_serde(&login::Request {
                            identifier,
                            password,
                        })
                        .unwrap();
                        log!("Sending login request:", &body);
                        let response = Request::post("/login")
                            .body(body) // fix this with a stringify
                            .unwrap()
                            .send()
                            .await
                            .expect("Unable to communicate with server")
                            .text()
                            .await
                            .expect("Unable to decode response");
                        log!("response:", JsValue::from_str(&response));
                        // log!("LoginResponse:", JsValue::from_serde(&response).unwrap());
                    });
                    return false;
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
                            <button onclick={ctx.link().callback(|_| Msg::Login)}>{"Login"}</button>
                        </div>
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
