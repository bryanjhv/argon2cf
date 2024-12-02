use worker::{Context, Env, Request, Response};

#[worker::event(fetch)]
async fn main(_req: Request, _env: Env, _ctx: Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();
    Response::ok("Hello, worker!")
}
