use std::net::IpAddr;
use rocket::http::Status;
use rocket::request::{FromRequest, Request, Outcome};

/// Request guard per ottenere l'IP reale del client
pub struct ClientRealAddr(pub IpAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientRealAddr {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Prova a ottenere l'IP dall'header X-Forwarded-For (se dietro proxy)
        if let Some(forwarded) = req.headers().get_one("X-Forwarded-For") {
            if let Ok(ip) = forwarded.split(',').next().unwrap_or("").trim().parse() {
                return Outcome::Success(ClientRealAddr(ip));
            }
        }
        
        // Altrimenti usa l'IP dalla connessione diretta
        match req.client_ip() {
            Some(ip) => Outcome::Success(ClientRealAddr(ip)),
            None => Outcome::Forward(Status::BadRequest),
        }
    }
}
