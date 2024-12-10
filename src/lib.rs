use argon2::{
    password_hash::{rand_core::OsRng, Error, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use worker::{Context, Env, Method, Request, Response};

#[worker::event(fetch)]
async fn main(mut req: Request, _env: Env, _ctx: Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();
    if req.method() != Method::Post {
        return Response::error("only-post-allowed", 405);
    }
    let Ok(form) = req.form_data().await else {
        return Response::error("only-form-data", 400);
    };
    let Some(f_pass) = form.get_field("pass") else {
        return Response::error("missing-pass-field", 400);
    };
    let argon2 = Argon2::default();
    if let Some(f_hash) = form.get_field("hash") {
        let Ok(hash) = PasswordHash::new(f_hash.as_str()) else {
            return Response::error("invalid-hash-field", 400);
        };
        match argon2.verify_password(f_pass.as_bytes(), &hash) {
            Ok(_) => Response::ok("true"),
            Err(Error::Password) => Response::ok("false"),
            Err(_) => Response::error("error-while-verify", 500),
        }
    } else {
        let salt = SaltString::generate(&mut OsRng);
        let Ok(hash) = argon2.hash_password(f_pass.as_bytes(), &salt) else {
            return Response::error("error-while-hash", 500);
        };
        Response::ok(hash.to_string())
    }
}
