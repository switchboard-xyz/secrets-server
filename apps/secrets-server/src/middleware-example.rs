// use poem::{get, middleware, route, web::Path, EndpointExt, MiddlewareExt, RouteMethodExt};
// use poem::{Request, Response};
//  // pnpm docker:build
// struct PrintMiddleware;

// #[poem::async_trait]
// impl middleware::Middleware for PrintMiddleware {
//     async fn handle(&self, req: Request, next: middleware::Next<'_>) -> poem::Result<Response> {
//         println!("Handling request: {:?}", req);
//         let resp = next.run(req).await;
//         println!("Finished handling request");
//         resp
//     }
// }

// #[get("/{id}")]
// async fn get_item(Path((id,)): Path<(String,)>) -> String {
//     format!("Item id: {}", id)
// }

// #[get("/user/{name}")]
// async fn get_user(Path((name,)): Path<(String,)>) -> String {
//     format!("User name: {}", name)
// }

// fn main() {
//     let app = route()
//         .at("/item", get_item.with(PrintMiddleware))
//         .at("/user", get_user.with(PrintMiddleware));
//     poem::Server::bind("127.0.0.1:3000")
//         .await
//         .unwrap()
//         .run(app)
//         .await
//         .unwrap();
// }
