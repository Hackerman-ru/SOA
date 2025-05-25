use crate::reactions::{reaction_service_client::ReactionServiceClient, *};
use tonic::{Status, transport::Channel};

type ReactionClient = ReactionServiceClient<Channel>;

#[derive(Debug, Clone)]
pub struct ReactionService {
    client: ReactionClient,
}

impl ReactionService {
    pub async fn new(addr: String) -> Result<Self, Status> {
        loop {
            let client = ReactionServiceClient::connect(addr.clone()).await;
            if let Ok(client) = client {
                return Ok(Self { client });
            }
        }
    }

    pub async fn get_post_stats(
        &mut self,
        request: PostRequest,
    ) -> Result<PostStatsResponse, Status> {
        self.client
            .get_post_stats(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_view_dynamics(
        &mut self,
        request: PostRequest,
    ) -> Result<TimeSeriesResponse, Status> {
        self.client
            .get_view_dynamics(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_like_dynamics(
        &mut self,
        request: PostRequest,
    ) -> Result<TimeSeriesResponse, Status> {
        self.client
            .get_like_dynamics(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_comment_dynamics(
        &mut self,
        request: PostRequest,
    ) -> Result<TimeSeriesResponse, Status> {
        self.client
            .get_comment_dynamics(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_top_posts(&mut self, request: TopRequest) -> Result<TopPostsResponse, Status> {
        self.client
            .get_top_posts(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_top_creators(
        &mut self,
        request: TopRequest,
    ) -> Result<TopUsersResponse, Status> {
        self.client
            .get_top_creators(request)
            .await
            .map(|r| r.into_inner())
    }
}
