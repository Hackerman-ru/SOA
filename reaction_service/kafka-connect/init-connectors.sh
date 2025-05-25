#!/bin/bash

function create_connector() {
    local topic=$1
    local event_type=$2
    local connector_name="clickhouse-sink-$topic"
    
    status=$(curl -s -o /dev/null -w "%{http_code}" http://kafka-connect:8083/connectors/$connector_name)
    
    if [ "$status" -ne 200 ]; then
        echo "Creating new connector: $connector_name"
        curl -X POST http://kafka-connect:8083/connectors \
             -H "Content-Type: application/json" \
             -d "$(generate_config $topic $event_type)"
    fi
    echo ""
}

function generate_config() {
    local topic=$1
    local event_type=$2
    cat <<EOF
{
    "name": "clickhouse-sink-$topic",
    "config": {
        "connector.class": "com.clickhouse.kafka.connect.ClickHouseSinkConnector",
        "tasks.max": "1",
        "topics": "$topic",

        "hostname": "clickhouse",
        "port": "8123",
        "database": "default",
        "topic2TableMap": "$topic=events",

        "key.converter": "org.apache.kafka.connect.storage.StringConverter",
        "value.converter": "org.apache.kafka.connect.json.JsonConverter",
        "value.converter.schemas.enable": "false",
        "schemas.enable": "false",

        "transforms": "insertEventType",
        "transforms.insertEventType.type": "org.apache.kafka.connect.transforms.InsertField\$Value",
        "transforms.insertEventType.static.field": "event_type",
        "transforms.insertEventType.static.value": "$event_type"
    }
}
EOF
}

create_connector "post-view" "view"
create_connector "post-like" "like"
create_connector "post-comment" "comment"