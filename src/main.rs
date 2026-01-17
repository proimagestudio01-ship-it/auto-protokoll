#[macro_use]
extern crate rocket;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{NaiveDate, Utc};
use rand::RngCore;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar};
use rocket::response::Redirect;
use rocket_dyn_templates::Template;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

#[derive(Clone)]
struct AppState {
    db: PgPool,
}

const COOKIE_USER: &str = "uid";

fn require_user(cookies: &CookieJar<'_>) -> Result<Uuid, Redirect> {
    cookies
        .get_private(COOKIE_USER)
        .and_then(|c| Uuid::parse_str(c.value()).ok())
        .ok_or(Redirect::to(uri!(login_page)))
}

fn hash_password(password: &str) -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let salt_str = argon2::password_hash::SaltString::b64_encode(&salt).unwrap();

    Argon2::default()
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap()
        .to_string()
}

fn verify_password(hash: &str, password: &str) -> bool {
    let parsed = PasswordHash::new(hash);
    if parsed.is_err() {
        return false;
    }
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed.unwrap())
        .is_ok()
}

#[derive(serde::Serialize)]
struct HandoverRow {
    datum: NaiveDate,
    kennzeichen: String,
    kraftstoff_prozent: i32,
    created_at: String,
}

#[get("/login")]
fn login_page() -> Template {
    Template::render("login", rocket::serde::json::json!({ "error": null }))
}

#[derive(FromForm)]
struct LoginForm {
    username: String,
    password: String,
}

#[post("/login", data = "<f>")]
async fn login_post(
    f: Form<LoginForm>,
    cookies: &CookieJar<'_>,
    state: &rocket::State<AppState>,
) -> Result<Redirect, Template> {
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE username = $1")
        .bind(&f.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| Template::render("login", rocket::serde::json::json!({"error":"Serverfehler"})))?;

    let Some(row) = row else {
        return Err(Template::render("login", rocket::serde::json::json!({"error":"Ungültige Zugangsdaten"})));
    };

    let uid: Uuid = row.get("id");
    let ph: String = row.get("password_hash");

    if !verify_password(&ph, &f.password) {
        return Err(Template::render("login", rocket::serde::json::json!({"error":"Ungültige Zugangsdaten"})));
    }

    cookies.add_private(Cookie::new(COOKIE_USER, uid.to_string()));
    Ok(Redirect::to(uri!(list_handovers)))
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove_private(Cookie::named(COOKIE_USER));
    Redirect::to(uri!(login_page))
}

#[get("/")]
async fn list_handovers(cookies: &CookieJar<'_>, state: &rocket::State<AppState>) -> Result<Template, Redirect> {
    let _uid = require_user(cookies)?;

    let rows = sqlx::query(
        r#"SELECT datum, kennzeichen, kraftstoff_prozent, created_at
           FROM handovers
           ORDER BY created_at DESC
           LIMIT 200"#,
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let handovers: Vec<HandoverRow> = rows
        .into_iter()
        .map(|r| HandoverRow {
            datum: r.get("datum"),
            kennzeichen: r.get("kennzeichen"),
            kraftstoff_prozent: r.get("kraftstoff_prozent"),
            created_at: r.get::<chrono::DateTime<Utc>, _>("created_at").to_rfc3339(),
        })
        .collect();

    Ok(Template::render("list", rocket::serde::json::json!({ "handovers": handovers })))
}

#[get("/new")]
fn new_page(cookies: &CookieJar<'_>) -> Result<Template, Redirect> {
    require_user(cookies)?;
    Ok(Template::render("new", rocket::serde::json::json!({ "error": null })))
}

#[derive(FromForm)]
struct NewHandoverForm {
    datum: String,
    kennzeichen: String,
    kraftstoff_prozent: i32,
}

#[post("/new", data = "<f>")]
async fn new_post(
    cookies: &CookieJar<'_>,
    state: &rocket::State<AppState>,
    f: Form<NewHandoverForm>,
) -> Result<Redirect, Template> {
    let uid = require_user(cookies)
        .map_err(|_| Template::render("login", rocket::serde::json::json!({"error":"Bitte anmelden"})))?;

    let datum = NaiveDate::parse_from_str(&f.datum, "%Y-%m-%d")
        .map_err(|_| Template::render("new", rocket::serde::json::json!({"error":"Ungültiges Datum"})))?;

    if !(0..=100).contains(&f.kraftstoff_prozent) {
        return Err(Template::render("new", rocket::serde::json::json!({"error":"Kraftstoffstand muss zwischen 0 und 100 liegen"})));
    }

    let kennzeichen = f.kennzeichen.trim();
    if kennzeichen.len() < 3 || kennzeichen.len() > 20 {
        return Err(Template::render("new", rocket::serde::json::json!({"error":"Kennzeichen ist ungültig"})));
    }

    sqlx::query("INSERT INTO handovers (id, created_by, datum, kennzeichen, kraftstoff_prozent) VALUES ($1,$2,$3,$4,$5)")
        .bind(Uuid::new_v4())
        .bind(uid)
        .bind(datum)
        .bind(kennzeichen)
        .bind(f.kraftstoff_prozent)
        .execute(&state.db)
        .await
        .map_err(|_| Template::render("new", rocket::serde::json::json!({"error":"Speichern fehlgeschlagen"})))?;

    Ok(Redirect::to(uri!(list_handovers)))
}

/// Creează user (max 10). Folosești doar la început:
/// /setup?u=admin&p=ParolaTa
#[get("/setup?<u>&<p>")]
async fn setup(u: &str, p: &str, state: &rocket::State<AppState>) -> Result<&'static str, &'static str> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .map_err(|_| "DB error")?;

    if count >= 10 {
        return Err("Max. 10 Benutzer erreicht");
    }

    let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM users WHERE username=$1")
        .bind(u)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| "DB error")?;

    if exists.is_some() {
        return Err("Benutzer existiert bereits");
    }

    let hash = hash_password(p);

    sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(u)
        .bind(hash)
        .execute(&state.db)
        .await
        .map_err(|_| "DB error")?;

    Ok("OK: Benutzer angelegt. Danach /login nutzen.")
}

#[launch]
async fn rocket() -> _ {
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL missing");

    let pool = PgPoolOptions::new()
    .max_connections(5)
    .acquire_timeout(Duration::from_secs(10))
    .connect(&db_url)
    .await
    .expect("DB connect failed");


    rocket::build()
        .manage(AppState { db: pool })
        .attach(Template::fairing())
        .mount("/", routes![login_page, login_post, logout, list_handovers, new_page, new_post, setup])
}
