CREATE TABLE events (
    event_type Enum8('view'=1, 'like'=2, 'comment'=3),
    creator_id UUID,
    post_id UUID,
    user_id UUID,
    timestamp DateTime64(3, 'UTC')
) ENGINE = MergeTree
ORDER BY (post_id, timestamp)
PARTITION BY toYYYYMM(timestamp);

CREATE TABLE post_metrics (
    date Date,
    post_id UUID,
    views UInt64,
    likes UInt64,
    comments UInt64
) ENGINE = SummingMergeTree
ORDER BY (date, post_id)
PARTITION BY toYYYYMM(date);

CREATE TABLE creator_metrics (
    date Date,
    creator_id UUID,
    views UInt64,
    likes UInt64,
    comments UInt64
) ENGINE = SummingMergeTree
ORDER BY (date, creator_id)
PARTITION BY toYYYYMM(date);

CREATE MATERIALIZED VIEW post_metrics_mv TO post_metrics AS
SELECT
    date(timestamp) AS date,
    post_id,
    countIf(event_type = 'view') AS views,
    countIf(event_type = 'like') AS likes,
    countIf(event_type = 'comment') AS comments
FROM events
GROUP BY date, post_id, creator_id;

CREATE MATERIALIZED VIEW creator_metrics_mv TO creator_metrics AS
SELECT
    date(timestamp) AS date,
    creator_id,
    countIf(event_type = 'view') AS views,
    countIf(event_type = 'like') AS likes,
    countIf(event_type = 'comment') AS comments
FROM events
GROUP BY date, creator_id;

