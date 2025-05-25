use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct ClickHouseClient {
    client: Client,
}

impl ClickHouseClient {
    pub async fn new(url: &str) -> Result<Self, clickhouse::error::Error> {
        let client = Client::default().with_url(url);
        Ok(Self { client })
    }

    pub async fn get_stats(
        &self,
        post_id: Uuid,
    ) -> Result<Option<Stats>, clickhouse::error::Error> {
        let id = post_id.to_string();
        let stats = self
            .client
            .query(
                "SELECT
                    sum(views) AS total_views,
                    sum(likes) AS total_likes,
                    sum(comments) AS total_comments
                FROM post_metrics
                WHERE post_id = ?",
            )
            .bind(&id)
            .fetch_optional::<Stats>()
            .await?;
        Ok(stats)
    }

    pub async fn get_dynamics(
        &self,
        stat: &str,
        post_id: Uuid,
    ) -> Result<Vec<(String, u64)>, clickhouse::error::Error> {
        let query = format!(
            "SELECT
                toString(date),
                sum({})
            FROM post_metrics
            WHERE post_id = ?
            GROUP BY date
            ORDER BY date",
            stat
        );
        let dynamics: Vec<(String, u64)> =
            self.client.query(&query).bind(post_id).fetch_all().await?;
        Ok(dynamics)
    }

    pub async fn get_top_posts(
        &self,
        stat: &str,
    ) -> Result<Vec<(Uuid, u64)>, clickhouse::error::Error> {
        let query = format!(
            "SELECT
                post_id,
                sum({}) AS total
            FROM post_metrics
            GROUP BY post_id
            ORDER BY total DESC
            LIMIT 10",
            stat
        );
        let top = self.client.query(&query).fetch_all::<Top>().await?;
        Ok(top.iter().map(|t| (t.uid, t.total)).collect())
    }

    pub async fn get_top_creators(
        &self,
        stat: &str,
    ) -> Result<Vec<(Uuid, u64)>, clickhouse::error::Error> {
        let query = format!(
            "SELECT
                creator_id,
                sum({}) AS total
            FROM creator_metrics
            GROUP BY creator_id
            ORDER BY total DESC
            LIMIT 10",
            stat
        );
        let top = self.client.query(&query).fetch_all::<Top>().await?;
        Ok(top.iter().map(|t| (t.uid, t.total)).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Default, Row, Serialize, Deserialize)]
pub struct Stats {
    pub total_views: u64,
    pub total_likes: u64,
    pub total_comments: u64,
}

#[derive(Row, Serialize, Deserialize)]
struct Top {
    #[serde(with = "clickhouse::serde::uuid")]
    uid: uuid::Uuid,
    total: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clickhouse::test;
    use uuid::uuid;

    #[tokio::test]
    async fn test_get_stats_success() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let stats = Stats {
            total_views: 100,
            total_likes: 20,
            total_comments: 5,
        };
        let post_id = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");

        mock.add(test::handlers::provide(vec![stats.clone()]));
        let result = client.get_stats(post_id).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.unwrap(), stats);
    }

    #[tokio::test]
    async fn test_get_stats_empty() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let post_id = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");

        mock.add(test::handlers::provide(Vec::<Stats>::new()));

        let result = client.get_stats(post_id).await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_dynamics_success() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let post_id = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");
        let expected = vec![
            ("2023-10-01".to_string(), 50),
            ("2023-10-02".to_string(), 30),
        ];

        mock.add(test::handlers::provide(expected.clone()));
        let result = client.get_dynamics("likes", post_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_get_dynamics_empty() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let post_id = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");

        mock.add(test::handlers::provide(Vec::<(String, u64)>::new()));
        let result = client.get_dynamics("comments", post_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_top_posts_success() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let expected = vec![
            (uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"), 1000),
            (uuid!("67e55044-10b1-426f-9247-bb680e5fe0c9"), 800),
        ];

        let top_data: Vec<Top> = expected
            .iter()
            .map(|(uid, total)| Top {
                uid: *uid,
                total: *total,
            })
            .collect();
        mock.add(test::handlers::provide(top_data));
        let result = client.get_top_posts("views").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_get_top_posts_empty() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();

        mock.add(test::handlers::provide(Vec::<Top>::new()));
        let result = client.get_top_posts("likes").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_top_creators_success() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let expected = vec![
            (uuid!("77e55044-10b1-426f-9247-bb680e5fe0c8"), 5000),
            (uuid!("77e55044-10b1-426f-9247-bb680e5fe0c9"), 4000),
        ];

        let top_data: Vec<Top> = expected
            .iter()
            .map(|(uid, total)| Top {
                uid: *uid,
                total: *total,
            })
            .collect();
        mock.add(test::handlers::provide(top_data));
        let result = client.get_top_creators("likes").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_get_top_creators_empty() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();

        mock.add(test::handlers::provide(Vec::<Top>::new()));
        let result = client.get_top_creators("comments").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_dynamics_error_handling() {
        let mock = test::Mock::new();
        let client = ClickHouseClient::new(mock.url()).await.unwrap();
        let post_id = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8");

        mock.add(test::handlers::failure(test::status::INTERNAL_SERVER_ERROR));
        let result = client.get_dynamics("views", post_id).await;
        assert!(result.is_err());
    }
}
