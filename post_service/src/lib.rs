use std::str::FromStr;
use std::sync::Arc;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use cdrs_tokio::cluster::session::{Session, SessionBuilder, TcpSessionBuilder};
use cdrs_tokio::cluster::{NodeTcpConfigBuilder, PagerState, TcpConnectionManager};
use cdrs_tokio::frame::TryFromRow;
use cdrs_tokio::load_balancing::RoundRobinLoadBalancingStrategy;
use cdrs_tokio::query::query_values::QueryValues;
use cdrs_tokio::query::QueryParamsBuilder;
use cdrs_tokio::query_values;
use cdrs_tokio::transport::TransportTcp;
use cdrs_tokio::types::CBytes;
use cdrs_tokio::{IntoCdrsValue, TryFromRow};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tonic::{Request, Response, Status};
use uuid::Uuid;

mod posts {
    include!("posts.rs");
}

use posts::{
    post_service_server::{PostService, PostServiceServer},
    CreatePostRequest, DeletePostRequest, DeletePostResponse, GetPostRequest, ListPostsRequest,
    ListPostsResponse, Post, PostResponse, UpdatePostRequest,
};

#[derive(Debug, thiserror::Error)]
pub enum PostError {
    #[error("Cassandra error: {0}")]
    CassandraError(String),
    #[error("Post not found")]
    NotFound,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Invalid UUID")]
    InvalidUuid,
    #[error("Invalid page token")]
    InvalidPageToken,
}

impl From<PostError> for Status {
    fn from(err: PostError) -> Self {
        match err {
            PostError::CassandraError(msg) => Status::internal(msg),
            PostError::NotFound => Status::not_found("Post not found"),
            PostError::PermissionDenied => Status::permission_denied("Permission denied"),
            PostError::InvalidUuid => Status::invalid_argument("Invalid UUID"),
            PostError::InvalidPageToken => Status::invalid_argument("Invalid page token"),
        }
    }
}

#[async_trait]
pub trait Generator: Send + Sync {
    fn new_v4(&self) -> Uuid;
}

pub struct UuidGenerator;

impl UuidGenerator {
    fn new() -> Self {
        Self
    }
}

impl Generator for UuidGenerator {
    fn new_v4(&self) -> Uuid {
        Uuid::new_v4()
    }
}

#[async_trait]
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub struct RealClock;

impl RealClock {
    fn new() -> Self {
        Self
    }
}

impl Clock for RealClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[async_trait]
pub trait CassandraClient: Send + Sync {
    async fn query(&self, query: &str) -> Result<(), PostError>;
    async fn query_with_values(&self, query: &str, values: QueryValues) -> Result<(), PostError>;
    async fn query_and_get_db_posts(&self, query: &str) -> Result<Vec<DbPost>, PostError>;
    async fn query_with_values_and_get_db_posts(
        &self,
        query: &str,
        values: QueryValues,
    ) -> Result<Vec<DbPost>, PostError>;
    async fn query_paged(
        &self,
        query: &str,
        values: QueryValues,
        page_size: i32,
        paging_state: Option<Vec<u8>>,
    ) -> Result<(Vec<DbPost>, Option<Vec<u8>>), PostError>;
}

#[derive(Debug, Clone)]
pub struct CassandraSession {
    session: Arc<
        Session<
            TransportTcp,
            TcpConnectionManager,
            RoundRobinLoadBalancingStrategy<TransportTcp, TcpConnectionManager>,
        >,
    >,
}

fn parse_rows(rows: Vec<cdrs_tokio::types::rows::Row>) -> Result<Vec<DbPost>, PostError> {
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let post =
            DbPost::try_from_row(row).map_err(|e| PostError::CassandraError(e.to_string()))?;
        result.push(post);
    }
    Ok(result)
}

#[async_trait]
impl CassandraClient for CassandraSession {
    async fn query(&self, query: &str) -> Result<(), PostError> {
        self.session
            .query(query)
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?;
        Ok(())
    }

    async fn query_with_values(&self, query: &str, values: QueryValues) -> Result<(), PostError> {
        self.session
            .query_with_values(query, values)
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?;
        Ok(())
    }

    async fn query_and_get_db_posts(&self, query: &str) -> Result<Vec<DbPost>, PostError> {
        let rows = self
            .session
            .query(query)
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?
            .response_body()
            .map_err(|e| PostError::CassandraError(e.to_string()))?
            .into_rows()
            .unwrap_or_default();

        parse_rows(rows)
    }

    async fn query_with_values_and_get_db_posts(
        &self,
        query: &str,
        values: QueryValues,
    ) -> Result<Vec<DbPost>, PostError> {
        let rows = self
            .session
            .query_with_values(query, values)
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?
            .response_body()
            .map_err(|e| PostError::CassandraError(e.to_string()))?
            .into_rows()
            .unwrap_or_default();

        parse_rows(rows)
    }

    async fn query_paged(
        &self,
        query: &str,
        values: QueryValues,
        page_size: i32,
        paging_state: Option<Vec<u8>>,
    ) -> Result<(Vec<DbPost>, Option<Vec<u8>>), PostError> {
        let mut pager = self.session.paged(page_size);

        let state = match paging_state {
            Some(state) => PagerState::new_with_cursor(CBytes::new(state)),
            None => PagerState::new(),
        };
        let query_params = QueryParamsBuilder::new()
            .with_page_size(page_size)
            .with_values(values)
            .build();

        let mut query_pager = pager.query_with_pager_state_params(query, state, query_params);

        let rows = query_pager
            .next()
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?;

        let next_paging_state = match query_pager.has_more() {
            true => query_pager
                .into_pager_state()
                .into_cursor()
                .and_then(|c| c.into_bytes()),
            false => None,
        };

        Ok((parse_rows(rows)?, next_paging_state))
    }
}

impl CassandraSession {
    pub async fn new(contact_points: &[&str]) -> Result<Self, PostError> {
        let mut builder = NodeTcpConfigBuilder::new();
        for &contact_point in contact_points {
            builder = builder.with_contact_point(contact_point.into());
        }
        let cluster_config = builder
            .build()
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?;

        let session =
            TcpSessionBuilder::new(RoundRobinLoadBalancingStrategy::new(), cluster_config)
                .build()
                .await
                .map_err(|e| PostError::CassandraError(e.to_string()))?;

        Ok(Self {
            session: Arc::new(session),
        })
    }

    pub async fn create_schema(&self) -> Result<(), PostError> {
        let create_keyspace = r#"
            CREATE KEYSPACE IF NOT EXISTS post_service 
            WITH replication = {
                'class': 'SimpleStrategy',
                'replication_factor': 1
            }
        "#;

        let create_table = r#"
            CREATE TABLE IF NOT EXISTS post_service.posts (
                id UUID PRIMARY KEY,
                title TEXT,
                description TEXT,
                creator_id UUID,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                is_private BOOLEAN,
                tags SET<TEXT>
            )
        "#;

        self.session
            .query(create_keyspace)
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?;

        self.session
            .query(create_table)
            .await
            .map_err(|e| PostError::CassandraError(e.to_string()))?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct PostServiceImpl {
    cassandra: Arc<dyn CassandraClient>,
    clock: Arc<dyn Clock>,
    generator: Arc<dyn Generator>,
}

impl PostServiceImpl {
    pub fn new(
        cassandra: Arc<dyn CassandraClient>,
        clock: Arc<dyn Clock>,
        generator: Arc<dyn Generator>,
    ) -> Self {
        Self {
            cassandra,
            clock,
            generator,
        }
    }

    async fn get_post_by_id(&self, id: Uuid, user_id: Option<Uuid>) -> Result<Post, PostError> {
        let query = "SELECT * FROM post_service.posts WHERE id = ?";
        let db_posts = self
            .cassandra
            .query_with_values_and_get_db_posts(query, query_values!(id))
            .await?;

        let db_post = db_posts.first().ok_or(PostError::NotFound)?;

        if db_post.is_private {
            if let Some(user_id) = user_id {
                if db_post.creator_id != user_id {
                    return Err(PostError::PermissionDenied);
                }
            } else {
                return Err(PostError::PermissionDenied);
            }
        }

        Ok(db_post.clone().into())
    }
}

#[tonic::async_trait]
impl PostService for PostServiceImpl {
    async fn create_post(
        &self,
        request: Request<CreatePostRequest>,
    ) -> Result<Response<PostResponse>, Status> {
        let req = request.into_inner();
        let creator_id = Uuid::parse_str(&req.creator_id).map_err(|_| PostError::InvalidUuid)?;
        let id = self.generator.new_v4();
        let now = self.clock.now();

        let db_post = DbPost {
            id,
            title: req.title,
            description: req.description,
            creator_id,
            created_at: now,
            updated_at: now,
            is_private: req.is_private,
            tags: req.tags.into_iter().collect(),
        };

        let query = r#"
            INSERT INTO post_service.posts 
            (id, title, description, creator_id, created_at, updated_at, is_private, tags) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        self.cassandra
            .query_with_values(
                query,
                query_values!(
                    db_post.id,
                    db_post.title.clone(),
                    db_post.description.clone(),
                    db_post.creator_id,
                    db_post.created_at,
                    db_post.updated_at,
                    db_post.is_private,
                    db_post.tags.clone()
                ),
            )
            .await?;

        Ok(Response::new(PostResponse {
            post: Some(db_post.into()),
        }))
    }

    async fn get_post(
        &self,
        request: Request<GetPostRequest>,
    ) -> Result<Response<PostResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| PostError::InvalidUuid)?;
        let user_id = Uuid::parse_str(&req.user_id).ok();

        let post = self.get_post_by_id(id, user_id).await?;
        Ok(Response::new(PostResponse { post: Some(post) }))
    }

    async fn update_post(
        &self,
        request: Request<UpdatePostRequest>,
    ) -> Result<Response<PostResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| PostError::InvalidUuid)?;
        let user_id = Uuid::parse_str(&req.user_id).map_err(|_| PostError::InvalidUuid)?;

        let mut post = self
            .get_post_by_id(id, Some(user_id))
            .await?
            .into_inner()
            .ok_or(PostError::NotFound)?;

        if post.creator_id != req.user_id {
            return Err(PostError::PermissionDenied.into());
        }

        post.title = req.title;
        post.description = req.description;
        post.is_private = req.is_private;
        post.tags = req.tags;
        post.updated_at = self.clock.now().to_rfc3339();

        let db_post = DbPost::try_from(post.clone()).map_err(|_| PostError::InvalidUuid)?;

        let query = r#"
            UPDATE post_service.posts 
            SET title = ?, description = ?, updated_at = ?, is_private = ?, tags = ?
            WHERE id = ?
        "#;

        self.cassandra
            .query_with_values(
                query,
                query_values!(
                    db_post.title,
                    db_post.description,
                    db_post.updated_at,
                    db_post.is_private,
                    db_post.tags,
                    db_post.id
                ),
            )
            .await?;

        Ok(Response::new(PostResponse { post: Some(post) }))
    }

    async fn delete_post(
        &self,
        request: Request<DeletePostRequest>,
    ) -> Result<Response<DeletePostResponse>, Status> {
        let req = request.into_inner();
        let id = Uuid::parse_str(&req.id).map_err(|_| PostError::InvalidUuid)?;
        let user_id = Uuid::parse_str(&req.user_id).map_err(|_| PostError::InvalidUuid)?;

        let post = self.get_post_by_id(id, Some(user_id)).await?;

        if post.creator_id != req.user_id {
            return Err(PostError::PermissionDenied.into());
        }

        let query = "DELETE FROM post_service.posts WHERE id = ?";
        self.cassandra
            .query_with_values(query, query_values!(id))
            .await?;

        Ok(Response::new(DeletePostResponse { success: true }))
    }

    async fn list_posts(
        &self,
        request: Request<ListPostsRequest>,
    ) -> Result<Response<ListPostsResponse>, Status> {
        let req = request.into_inner();

        let (query, values) = if req.tags.is_empty() {
            (
                "SELECT * FROM post_service.posts WHERE is_private = false ALLOW FILTERING"
                    .to_string(),
                query_values!(),
            )
        } else {
            let tags_placeholders = vec!["?".to_string(); req.tags.len()];
            (
                format!(
                    "SELECT * FROM post_service.posts WHERE is_private = false AND tags CONTAINS {} ALLOW FILTERING",
                    tags_placeholders.join(" AND tags CONTAINS ")
                ),
                QueryValues::from(req.tags),
            )
        };

        let page_size = req.page_size.clamp(1, 100);
        let paging_state = match req.page_token.is_empty() {
            false => Some(
                BASE64_STANDARD
                    .decode(&req.page_token)
                    .map_err(|_| PostError::InvalidPageToken)?,
            ),
            true => None,
        };

        let (db_posts, next_paging_state) = self
            .cassandra
            .query_paged(&query, values, page_size, paging_state)
            .await?;

        let next_page_token = next_paging_state
            .map(|b| BASE64_STANDARD.encode(b))
            .unwrap_or_default();

        let posts = db_posts.into_iter().map(Post::from).collect();

        Ok(Response::new(ListPostsResponse {
            posts,
            next_page_token,
        }))
    }
}

pub async fn create_server(
    cassandra: CassandraSession,
) -> Result<PostServiceServer<PostServiceImpl>, PostError> {
    cassandra.create_schema().await?;
    Ok(PostServiceServer::new(PostServiceImpl::new(
        Arc::new(cassandra),
        Arc::new(RealClock::new()),
        Arc::new(UuidGenerator::new()),
    )))
}

#[derive(Clone, Debug, IntoCdrsValue, TryFromRow, PartialEq)]
pub struct DbPost {
    id: Uuid,
    title: String,
    description: String,
    creator_id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    is_private: bool,
    tags: Vec<String>,
}

impl From<DbPost> for Post {
    fn from(db_post: DbPost) -> Self {
        Post {
            id: db_post.id.to_string(),
            title: db_post.title,
            description: db_post.description,
            creator_id: db_post.creator_id.to_string(),
            created_at: db_post.created_at.to_rfc3339(),
            updated_at: db_post.updated_at.to_rfc3339(),
            is_private: db_post.is_private,
            tags: db_post.tags.into_iter().collect(),
        }
    }
}

impl TryFrom<Post> for DbPost {
    type Error = PostError;

    fn try_from(post: Post) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&post.id).map_err(|_| PostError::InvalidUuid)?,
            title: post.title,
            description: post.description,
            creator_id: Uuid::parse_str(&post.creator_id).map_err(|_| PostError::InvalidUuid)?,
            created_at: DateTime::from_str(&post.created_at)
                .map_err(|_| PostError::CassandraError("Invalid created_at".to_string()))?,
            updated_at: DateTime::from_str(&post.updated_at)
                .map_err(|_| PostError::CassandraError("Invalid updated_at".to_string()))?,
            is_private: post.is_private,
            tags: post.tags.into_iter().collect(),
        })
    }
}

impl Post {
    fn into_inner(self) -> Option<Self> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::*;
    use tonic::Code;

    pub struct MockClock {
        mock_now: DateTime<Utc>,
    }

    impl MockClock {
        pub fn new(mock_now: DateTime<Utc>) -> Self {
            Self { mock_now }
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> DateTime<Utc> {
            self.mock_now
        }
    }

    pub struct MockGenerator {
        uuid: Uuid,
    }

    impl MockGenerator {
        pub fn new(uuid: Uuid) -> Self {
            Self { uuid }
        }
    }

    impl Generator for MockGenerator {
        fn new_v4(&self) -> Uuid {
            self.uuid
        }
    }

    mock! {
        pub CassandraClientImpl {}
        #[async_trait]
        impl CassandraClient for CassandraClientImpl {
            async fn query(&self, query: &str) -> Result<(), PostError>;
            async fn query_with_values(&self, query: &str, values: QueryValues) -> Result<(), PostError>;
            async fn query_and_get_db_posts(&self, query: &str) -> Result<Vec<DbPost>, PostError>;
            async fn query_with_values_and_get_db_posts(
                &self,
                query: &str,
                values: QueryValues,
            ) -> Result<Vec<DbPost>, PostError>;
            async fn query_paged(
                &self,
                query: &str,
                values: QueryValues,
                page_size: i32,
                paging_state: Option<Vec<u8>>,
            ) -> Result<(Vec<DbPost>, Option<Vec<u8>>), PostError>;
        }
    }

    fn create_test_post(uuid: Uuid, now: DateTime<Utc>) -> Post {
        let timestamp = now.to_rfc3339();
        Post {
            id: uuid.to_string(),
            title: "Test Post".into(),
            description: "Test Description".into(),
            creator_id: Uuid::new_v4().to_string(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            is_private: false,
            tags: vec!["test".into()],
        }
    }

    pub struct MockData {
        mock_cassandra: MockCassandraClientImpl,
        mock_clock: MockClock,
        mock_generator: MockGenerator,
        test_post: Post,
        db_post: DbPost,
    }

    impl MockData {
        fn new() -> Self {
            let fixed_time = Utc::now();
            let fixed_uuid = Uuid::new_v4();
            let mock_cassandra = MockCassandraClientImpl::new();
            let mock_clock = MockClock::new(fixed_time);
            let mock_generator = MockGenerator::new(fixed_uuid);
            let test_post = create_test_post(fixed_uuid, fixed_time);
            let db_post = DbPost::try_from(test_post.clone()).unwrap();
            Self {
                mock_cassandra,
                mock_clock,
                mock_generator,
                test_post,
                db_post,
            }
        }
    }

    #[tokio::test]
    async fn test_create_post_success() {
        let mut data = MockData::new();
        let query = r#"
            INSERT INTO post_service.posts 
            (id, title, description, creator_id, created_at, updated_at, is_private, tags) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        data.mock_cassandra
            .expect_query_with_values()
            .with(
                eq(query),
                eq(query_values!(
                    data.db_post.id,
                    data.db_post.title.clone(),
                    data.db_post.description.clone(),
                    data.db_post.creator_id,
                    data.db_post.created_at,
                    data.db_post.updated_at,
                    data.db_post.is_private,
                    data.db_post.tags.clone()
                )),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        let request = Request::new(CreatePostRequest {
            title: data.test_post.title,
            description: data.test_post.description,
            creator_id: data.test_post.creator_id,
            is_private: data.test_post.is_private,
            tags: data.test_post.tags.into_iter().collect(),
        });

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let response = service.create_post(request).await.unwrap();
        assert!(response.into_inner().post.is_some());
    }

    #[tokio::test]
    async fn test_get_post_success() {
        let mut data = MockData::new();

        data.mock_cassandra
            .expect_query_with_values_and_get_db_posts()
            .with(
                eq("SELECT * FROM post_service.posts WHERE id = ?"),
                eq(query_values!(data.db_post.id)),
            )
            .times(1)
            .returning(move |_, _| Ok(vec![data.db_post.clone()]));

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let request = Request::new(GetPostRequest {
            id: data.test_post.id.clone(),
            user_id: data.test_post.creator_id.clone(),
        });

        let response = service.get_post(request).await.unwrap();
        assert_eq!(response.into_inner().post.unwrap().id, data.test_post.id);
    }

    #[tokio::test]
    async fn test_get_post_permission_denied() {
        let mut data = MockData::new();
        data.db_post.is_private = true;
        data.test_post.is_private = true;

        data.mock_cassandra
            .expect_query_with_values_and_get_db_posts()
            .returning(move |_, _| Ok(vec![data.db_post.clone()]));

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let request = Request::new(GetPostRequest {
            id: data.test_post.id.clone(),
            user_id: Uuid::new_v4().to_string(),
        });

        let result = service.get_post(request).await;
        assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn test_update_post_success() {
        let mut data = MockData::new();
        let query = r#"
            UPDATE post_service.posts 
            SET title = ?, description = ?, updated_at = ?, is_private = ?, tags = ?
            WHERE id = ?
        "#;
        let updated_at = data.db_post.updated_at;
        let id = data.db_post.id;

        // Mock get_post
        data.mock_cassandra
            .expect_query_with_values_and_get_db_posts()
            .returning(move |_, _| Ok(vec![data.db_post.clone()]));

        // Mock update query
        data.mock_cassandra
            .expect_query_with_values()
            .with(
                eq(query),
                eq(query_values!(
                    "New Title",
                    "New Description",
                    updated_at,
                    true,
                    vec!["new_tag"],
                    id
                )),
            )
            .returning(|_, _| Ok(()));

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let request = Request::new(UpdatePostRequest {
            id: data.test_post.id.clone(),
            title: "New Title".into(),
            description: "New Description".into(),
            user_id: data.test_post.creator_id.clone(),
            is_private: true,
            tags: vec!["new_tag".into()],
        });

        let response = service.update_post(request).await.unwrap();
        let updated_post = response.into_inner().post.unwrap();
        assert_eq!(updated_post.title, "New Title");
        assert_eq!(updated_post.tags, vec!["new_tag"]);
    }

    #[tokio::test]
    async fn test_delete_post_success() {
        let mut data = MockData::new();
        let id = data.db_post.id;

        // Mock get_post
        data.mock_cassandra
            .expect_query_with_values_and_get_db_posts()
            .returning(move |_, _| Ok(vec![data.db_post.clone()]));

        // Mock delete query
        data.mock_cassandra
            .expect_query_with_values()
            .with(
                eq("DELETE FROM post_service.posts WHERE id = ?"),
                eq(query_values!(id)),
            )
            .returning(|_, _| Ok(()));

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let request = Request::new(DeletePostRequest {
            id: data.test_post.id.clone(),
            user_id: data.test_post.creator_id.clone(),
        });

        let response = service.delete_post(request).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_list_posts_pagination() {
        let mut data = MockData::new();

        let paging_state = Some(vec![1, 2, 3]);
        let encoded_paging_state = BASE64_STANDARD.encode(paging_state.clone().unwrap());

        data.mock_cassandra
            .expect_query_paged()
            .with(
                eq("SELECT * FROM post_service.posts WHERE is_private = false ALLOW FILTERING"),
                eq(query_values!()),
                eq(10),
                eq(None),
            )
            .returning(move |_, _, _, _| Ok((vec![data.db_post.clone()], paging_state.clone())));

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let request = Request::new(ListPostsRequest {
            user_id: data.test_post.creator_id,
            tags: vec![],
            page_size: 10,
            page_token: "".into(),
        });

        let response = service.list_posts(request).await.unwrap().into_inner();
        assert_eq!(response.posts.len(), 1);
        assert_eq!(response.next_page_token, encoded_paging_state);
    }

    #[tokio::test]
    async fn test_list_posts_pagination_with_tags() {
        let mut data = MockData::new();

        let paging_state = Some(vec![1, 2, 3]);
        let encoded_paging_state = BASE64_STANDARD.encode(paging_state.clone().unwrap());

        data.mock_cassandra
            .expect_query_paged()
            .with(
                eq("SELECT * FROM post_service.posts WHERE is_private = false AND tags CONTAINS ? ALLOW FILTERING"),
                eq(query_values!("test".to_string())),
                eq(10),
                eq(None),
            )
            .returning(move |_, _, _, _| Ok((vec![data.db_post.clone()], paging_state.clone())));

        let service = PostServiceImpl::new(
            Arc::new(data.mock_cassandra),
            Arc::new(data.mock_clock),
            Arc::new(data.mock_generator),
        );
        let request = Request::new(ListPostsRequest {
            user_id: data.test_post.creator_id,
            tags: vec!["test".to_string()],
            page_size: 10,
            page_token: "".into(),
        });

        let response = service.list_posts(request).await.unwrap().into_inner();
        assert_eq!(response.posts.len(), 1);
        assert_eq!(response.next_page_token, encoded_paging_state);
    }

    #[test]
    fn test_db_post_conversion() {
        let fixed_uuid = Uuid::new_v4();
        let fixed_time = Utc::now();
        let post = create_test_post(fixed_uuid, fixed_time);
        let db_post = DbPost::try_from(post.clone()).unwrap();
        let converted_post = Post::from(db_post);

        assert_eq!(post.id, converted_post.id);
        assert_eq!(post.title, converted_post.title);
        assert_eq!(post.tags, converted_post.tags);
    }

    #[test]
    fn test_error_conversion() {
        let not_found: Status = PostError::NotFound.into();
        assert_eq!(not_found.code(), Code::NotFound);

        let permission_denied: Status = PostError::PermissionDenied.into();
        assert_eq!(permission_denied.code(), Code::PermissionDenied);
    }
}
