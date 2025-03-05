use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use std::net::IpAddr;
use std::{convert::Infallible, net::SocketAddr};

async fn handle(client_ip: IpAddr, req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match hyper_reverse_proxy::call(client_ip, "http://user_service:8081", req).await {
        Ok(response) => Ok(response),
        Err(_error) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::empty())
            .unwrap()),
    }
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = ([0, 0, 0, 0], 8080).into();

    let make_svc = make_service_fn(|conn: &AddrStream| {
        let remote_addr = conn.remote_addr().ip();
        async move { Ok::<_, Infallible>(service_fn(move |req| handle(remote_addr, req))) }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("Running proxy-server on {:?}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

// use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, web};
// use reqwest::{self, Client, Response};
// use serde_json::json;

// async fn convert_response(response: Result<Response, reqwest::Error>) -> HttpResponse {
//     match response {
//         Ok(res) => {
//             let mut response_builder = HttpResponse::build(res.status());
//             for header in res.headers().iter() {
//                 response_builder.append_header(header);
//             }
//             if let Ok(body) = res.bytes().await {
//                 response_builder.body(body)
//             } else {
//                 response_builder.finish()
//             }
//         }
//         Err(err) => {
//             let err = format!("Failed to proxy request: {}", err.to_string());
//             HttpResponse::InternalServerError().json(json!({ "error": err }))
//         }
//     }
// }

// async fn proxy_request(
//     client: web::Data<Client>,
//     req: HttpRequest,
//     path: web::Path<String>,
// ) -> impl Responder {
//     let url = format!("http://user_service:8081/{}", path);
//     let mut request_builder = client.request(req.method().clone(), url);

//     for (header_name, header_value) in req.headers() {
//         request_builder = request_builder.header(header_name, header_value);
//     }

//     if let Some(body) = req. {
//         request_builder = request_builder.json(&body.into_inner());
//     }

//     let response = request_builder.send().await;
//     convert_response(response).await
// }

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     let client = Client::new();

//     HttpServer::new(move || {
//         App::new()
//             .app_data(web::Data::new(client.clone()))
//             .route("/{path:.*}", web::to(proxy_request))
//     })
//     .bind("0.0.0.0:8080")?
//     .run()
//     .await
// }
