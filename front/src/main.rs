use yew::prelude::*;

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
                <div class={"login"}>
                    <label for="identifier">{"Username / Email"}</label>
                    <input type="text" id="identifier" />
                    <label for="password">{"Password"}</label>
                    <input type="password" id="password" />
                    <button>{"Login"}</button>
                </div>
            </div>
        }
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}