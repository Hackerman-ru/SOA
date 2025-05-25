use std::net::SocketAddr;

use crate::clickhouse::ClickHouseClient;
use reactions::{
    PostRequest, PostStat, PostStatsResponse, TimePoint, TimeSeriesResponse, TopPostsResponse,
    TopRequest, TopUsersResponse, UserStat,
    reaction_service_server::{ReactionService, ReactionServiceServer},
    top_request::Metric,
};

use uuid::Uuid;

use tonic::{Request, Response, Status, transport::Server};

pub mod reactions {
    include!("reactions.rs");
}

pub async fn run_server(
    addr: SocketAddr,
    clickhouse: std::sync::Arc<ClickHouseClient>,
) -> Result<(), Box<dyn std::error::Error>> {
    let service = ReactionsServiceImpl { clickhouse };
    let svc = ReactionServiceServer::new(service);

    Server::builder().add_service(svc).serve(addr).await?;

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ReactionError {
    #[error("Clickhouse error: {0}")]
    ClickHouseError(String),
    #[error("Not found")]
    NotFound(String),
    #[error("Invalid UUID")]
    InvalidUuid,
}

impl From<ReactionError> for Status {
    fn from(err: ReactionError) -> Self {
        match err {
            ReactionError::ClickHouseError(msg) => Status::internal(msg),
            ReactionError::NotFound(msg) => Status::not_found(msg),
            ReactionError::InvalidUuid => Status::invalid_argument("Invalid UUID"),
        }
    }
}

struct ReactionsServiceImpl {
    clickhouse: std::sync::Arc<ClickHouseClient>,
}

impl ReactionsServiceImpl {
    async fn get_dynamics(
        &self,
        request: Request<PostRequest>,
        stat: &str,
    ) -> Result<Response<TimeSeriesResponse>, Status> {
        let post_id = Uuid::parse_str(&request.into_inner().post_id)
            .map_err(|_| ReactionError::InvalidUuid)?;

        let dynamics = self
            .clickhouse
            .get_dynamics(stat, post_id)
            .await
            .map_err(|e| ReactionError::ClickHouseError(e.to_string()))?;

        Ok(Response::new(TimeSeriesResponse {
            points: dynamics
                .into_iter()
                .map(|(date, count)| TimePoint { date, count })
                .collect(),
        }))
    }
}

#[tonic::async_trait]
impl ReactionService for ReactionsServiceImpl {
    async fn get_post_stats(
        &self,
        request: Request<PostRequest>,
    ) -> Result<Response<PostStatsResponse>, Status> {
        let post_id = Uuid::parse_str(&request.into_inner().post_id)
            .map_err(|_| ReactionError::InvalidUuid)?;

        let stats = self
            .clickhouse
            .get_stats(post_id)
            .await
            .map_err(|e| ReactionError::ClickHouseError(e.to_string()))?;

        match stats {
            Some(s) => Ok(Response::new(PostStatsResponse {
                views: s.total_views,
                likes: s.total_likes,
                comments: s.total_comments,
            })),
            None => Err(ReactionError::NotFound("Post not found".to_string()).into()),
        }
    }

    async fn get_view_dynamics(
        &self,
        request: Request<PostRequest>,
    ) -> Result<Response<TimeSeriesResponse>, Status> {
        self.get_dynamics(request, "views").await
    }

    async fn get_like_dynamics(
        &self,
        request: Request<PostRequest>,
    ) -> Result<Response<TimeSeriesResponse>, Status> {
        self.get_dynamics(request, "likes").await
    }

    async fn get_comment_dynamics(
        &self,
        request: Request<PostRequest>,
    ) -> Result<Response<TimeSeriesResponse>, Status> {
        self.get_dynamics(request, "comments").await
    }

    async fn get_top_posts(
        &self,
        request: Request<TopRequest>,
    ) -> Result<Response<TopPostsResponse>, Status> {
        let metric = request.into_inner().metric();

        let table = match metric {
            Metric::Views => "views",
            Metric::Likes => "likes",
            Metric::Comments => "comments",
        };

        let top = self
            .clickhouse
            .get_top_posts(table)
            .await
            .map_err(|e| ReactionError::ClickHouseError(e.to_string()))?;

        Ok(Response::new(TopPostsResponse {
            posts: top
                .into_iter()
                .map(|(post_id, count)| PostStat {
                    post_id: post_id.to_string(),
                    count,
                })
                .collect(),
        }))
    }

    async fn get_top_creators(
        &self,
        request: Request<TopRequest>,
    ) -> Result<Response<TopUsersResponse>, Status> {
        let metric = request.into_inner().metric();

        let table = match metric {
            Metric::Views => "views",
            Metric::Likes => "likes",
            Metric::Comments => "comments",
        };

        let top = self
            .clickhouse
            .get_top_creators(table)
            .await
            .map_err(|e| ReactionError::ClickHouseError(e.to_string()))?;

        Ok(Response::new(TopUsersResponse {
            users: top
                .into_iter()
                .map(|(user_id, count)| UserStat {
                    user_id: user_id.to_string(),
                    count,
                })
                .collect(),
        }))
    }
}
