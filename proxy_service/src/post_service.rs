use crate::posts::{post_service_client::PostServiceClient, *};
use tonic::{Status, transport::Channel};

type PostClient = PostServiceClient<Channel>;

#[derive(Debug, Clone)]
pub struct PostService {
    client: PostClient,
}

impl PostService {
    pub async fn new(addr: String) -> Result<Self, Status> {
        loop {
            let client = PostServiceClient::connect(addr.clone()).await;
            if let Ok(client) = client {
                return Ok(Self { client });
            }
        }
    }

    pub async fn create_post(
        &mut self,
        request: CreatePostRequest,
    ) -> Result<PostResponse, Status> {
        self.client
            .create_post(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_post(&mut self, request: GetPostRequest) -> Result<PostResponse, Status> {
        self.client.get_post(request).await.map(|r| r.into_inner())
    }

    pub async fn update_post(
        &mut self,
        request: UpdatePostRequest,
    ) -> Result<PostResponse, Status> {
        self.client
            .update_post(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn delete_post(
        &mut self,
        request: DeletePostRequest,
    ) -> Result<DeletePostResponse, Status> {
        self.client
            .delete_post(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn list_posts(
        &mut self,
        request: ListPostsRequest,
    ) -> Result<ListPostsResponse, Status> {
        self.client
            .list_posts(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn comment_post(
        &mut self,
        request: CommentPostRequest,
    ) -> Result<CommentPostResponse, Status> {
        self.client
            .comment_post(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn get_comments(
        &mut self,
        request: GetCommentsRequest,
    ) -> Result<GetCommentsResponse, Status> {
        self.client
            .get_comments(request)
            .await
            .map(|r| r.into_inner())
    }

    pub async fn like_post(
        &mut self,
        request: LikePostRequest,
    ) -> Result<LikePostResponse, Status> {
        self.client.like_post(request).await.map(|r| r.into_inner())
    }

    pub async fn view_post(
        &mut self,
        request: ViewPostRequest,
    ) -> Result<ViewPostResponse, Status> {
        self.client.view_post(request).await.map(|r| r.into_inner())
    }
}
