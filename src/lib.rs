use argon2::{
    password_hash::{Error, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use rand_core::OsRng;
use worker::{Context, Env, Method, Request, Response};

#[worker::event(fetch)]
async fn main(mut req: Request, _env: Env, _ctx: Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();
    if req.method() != Method::Post {
        return Response::error("only-post", 405);
    }
    let Ok(form) = req.form_data().await else {
        return Response::error("invalid-form", 400);
    };
    let Some(f_pass) = form.get_field("pass") else {
        return Response::error("missing-pass", 400);
    };
    let argon2 = Argon2::default();
    if let Some(f_hash) = form.get_field("hash") {
        let Ok(hash) = PasswordHash::new(f_hash.as_str()) else {
            return Response::error("invalid-hash", 400);
        };
        match argon2.verify_password(f_pass.as_bytes(), &hash) {
            Ok(_) => Response::ok("true"),
            Err(Error::Password) => Response::ok("false"),
            Err(_) => Response::error("verify-error", 500),
        }
    } else {
        let salt = SaltString::generate(&mut OsRng);
        let Ok(hash) = argon2.hash_password(f_pass.as_bytes(), &salt) else {
            return Response::error("hash-error", 500);
        };
        Response::ok(hash.to_string())
    }
}
