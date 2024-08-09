import http.client
import json
import logging
import os
import re
import boto3
import urllib.parse

# Boolean flag, which determins if the incoming even should be printed to the output.
LOG_EVENTS = os.getenv("LOG_EVENTS", "False").lower() in ("true", "1", "t", "yes", "y")

# Set the log level
logging.basicConfig()
log = logging.getLogger()
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


SLACK_WEBHOOK_URL_SOURCE_TYPE = os.getenv(
    "SLACK_WEBHOOK_URL_SOURCE_TYPE", "text"
).lower()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


def get_slack_credentials(value: str, source_type: str) -> str:
    if not value:
        raise RuntimeError(
            "The required env variable SLACK_WEBHOOK_URL is not set or empty!"
        )
    try:
        if source_type == "text":
            log.info("Getting slack credentials as plain text")
            return value

        elif source_type == "secretsmanager":
            log.info("Getting slack credentials from secretsmanager")
            secretsmanager = boto3.client("secretsmanager")
            secretsmanagerResponse = secretsmanager.get_secret_value(
                SecretId=value,
            )
            return secretsmanagerResponse["SecretString"]

        elif source_type == "ssm":
            log.info("Getting slack credentials from ssm")
            ssm = boto3.client("ssm")
            ssmResponse = ssm.get_parameter(
                Name=value,
                WithDecryption=True,
            )
            return ssmResponse["Parameter"]["Value"]
        else:
            raise RuntimeError(
                "SLACK_WEBHOOK_URL_SOURCE_TYPE is not valid, it should be one of: text, secretsmanager, ssm"
            )

    except Exception as e:
        raise RuntimeError(
            f"Error getting slack credentials from \
                {source_type} `{value}`: {e}"
        ) from e


if SLACK_WEBHOOK_URL_SOURCE_TYPE not in ("text", "secretsmanager", "ssm"):
    raise RuntimeError(
        "SLACK_WEBHOOK_URL_SOURCE_TYPE is not valid, it should be one of: text, secretsmanager, ssm"
    )

SLACK_WEBHOOK_URL = get_slack_credentials(
    SLACK_WEBHOOK_URL, SLACK_WEBHOOK_URL_SOURCE_TYPE
)

# ---------------------------------------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------------------------------------------------

# Input: EventBridge Message detail_type and detail
# Output: mrkdwn text


def ecs_events_parser(detail_type, detail):
    emoji_event_type = {
        "ERROR": ":exclamation:",
        "WARN": ":warning:",
        "INFO": ":information_source:",
    }
    emoji_event_name = {
        "SERVICE_DEPLOYMENT_IN_PROGRESS": ":arrows_counterclockwise:",
        "SERVICE_DEPLOYMENT_COMPLETED": ":white_check_mark:",
        "SERVICE_DEPLOYMENT_FAILED": ":x:",
    }
    emoji_task_status = {
        "PROVISIONING": ":clock1:",
        "PENDING": ":clock6:",
        "ACTIVATING": ":clock11:",
        "RUNNING": ":up:",
        "DEACTIVATING": ":arrow_backward:",
        "STOPPING": ":rewind:",
        "DEPROVISIONING": ":black_left_pointing_double_triangle_with_vertical_bar:",
        "STOPPED": ":black_square_for_stop:",
    }

    if detail_type == "ECS Container Instance State Change":
        result = (
            "*Instance ID:* "
            + detail["ec2InstanceId"]
            + "\n"
            + "• Status: "
            + detail["status"]
        )
        if "statusReason" in detail:
            result = result + "\n" + "• Reason: " + detail["statusReason"]
        return result

    if detail_type == "ECS Deployment State Change":
        result = (
            "*Event Detail:*"
            + emoji_event_type.get(detail["eventType"], "")
            + emoji_event_name.get(detail["eventName"], "")
            + "\n"
            + "• "
            + detail["eventType"]
            + " - "
            + detail["eventName"]
            + "\n"
            + "• Deployment: "
            + detail["deploymentId"]
            + "\n"
            + "• Reason: "
            + detail["reason"]
        )
        return result

    if detail_type == "ECS Service Action":
        result = (
            "*Event Detail:*"
            + emoji_event_type.get(detail["eventType"], "")
            + emoji_event_name.get(detail["eventName"], "")
            + "\n"
            + "• "
            + detail["eventType"]
            + " - "
            + detail["eventName"]
        )
        if "capacityProviderArns" in detail:
            capacity_providers = ""
            for capacity_provider in detail["capacityProviderArns"]:
                try:
                    capacity_providers = (
                        capacity_providers
                        + capacity_provider.split(":")[5].split("/")[1]
                        + ", "
                    )
                except Exception:
                    log.error(
                        "Error parsing clusterArn: `{}`".format(capacity_provider)
                    )
                    capacity_providers = capacity_providers + capacity_provider + ", "
            if capacity_providers != "":
                result = result + "\n" + "• Capacity Providers: " + capacity_providers
        return result

    if detail_type == "ECS Task State Change":
        container_instance_id = "UNKNOWN"
        if "containerInstanceArn" in detail:
            try:
                container_instance_id = (
                    detail["containerInstanceArn"].split(":")[5].split("/")[2]
                )
            except Exception:
                log.error(
                    "Error parsing containerInstanceArn: `{}`".format(
                        detail["containerInstanceArn"]
                    )
                )
                container_instance_id = detail["containerInstanceArn"]
        try:
            task_definition = (
                detail["taskDefinitionArn"].split(":")[5].split("/")[1]
                + ":"
                + detail["taskDefinitionArn"].split(":")[6]
            )
        except Exception:
            log.error(
                "Error parsing taskDefinitionArn: `{}`".format(
                    detail["taskDefinitionArn"]
                )
            )
            task_definition = detail["taskDefinitionArn"]
        try:
            detail["taskArn"].split(":")[5].split("/")[2]
        except Exception:
            log.error("Error parsing taskArn: `{}`".format(detail["taskArn"]))
            detail["taskArn"]
        result = (
            "*Event Detail:* "
            + "\n"
            + "• Task Definition: "
            + task_definition
            + "\n"
            + "• Last: "
            + detail["lastStatus"]
            + " "
            + emoji_task_status.get(detail["lastStatus"], "")
            + "\n"
            + "• Desired: "
            + detail["desiredStatus"]
            + " "
            + emoji_task_status.get(detail["desiredStatus"], "")
        )
        if container_instance_id != "UNKNOWN":
            result = result + "\n" + "• Instance ID: " + container_instance_id
        if detail["lastStatus"] == "RUNNING":
            if "healthStatus" in detail:
                result = result + "\n" + "• HealthStatus: " + detail["healthStatus"]
        if detail["lastStatus"] == "STOPPED":
            if "stopCode" in detail:
                result = result + "\n" + ":bangbang: Stop Code: " + detail["stopCode"]
            if "stoppedReason" in detail:
                result = (
                    result + "\n" + ":bangbang: Stop Reason: " + detail["stoppedReason"]
                )
            if "containers" in detail:
                result = result + "\n" + "Task containers and their exit code:"
                for container in detail["containers"]:
                    result = (
                        result
                        + "\n"
                        + " - "
                        + container["name"]
                        + ": "
                        + str(container.get("exitCode", "unknown"))
                    )
                    if str(container.get("exitCode", "unknown")) == "1":
                        log_group_name = (
                            "/ecs/"
                            + detail.get("group").split(":")[1].split("-service")[0]
                        )
                        log_stream_name = container.get("runtimeId").split("-")[0]
                        if log_group_name and log_stream_name:
                            logs = get_container_logs(log_group_name, log_stream_name)
                            result = result + "\n" + logs + "\n"
        return result

    return f"*Event Detail:* ```{json.dumps(detail, indent=4)}```"


def generate_cloudwatch_url(log_stream):
    # URL 인코딩
    log_stream_encoded = urllib.parse.quote(log_stream, safe="")

    # AWS CloudWatch URL 생성
    region = "ap-northeast-2"
    log_group = "/ecs/tlona-develop-cms-web-api"
    base_url = f"https://{region}.console.aws.amazon.com/cloudwatch/home"

    cloudwatch_url = f"{base_url}?region={region}#logsV2:log-groups/log-group/\
{urllib.parse.quote(log_group, safe='')}/log-events/{log_stream_encoded}"

    return cloudwatch_url


def get_container_logs(log_group_name, containerId):
    service_name = "-".join(log_group_name.split("/")[2].split("-")[2:])
    lsnp = f"{service_name}/tlona-{service_name}-container/{containerId}"
    client = boto3.client("logs")
    log_url = generate_cloudwatch_url(lsnp)
    try:
        log_streams = client.describe_log_streams(
            logGroupName=log_group_name,
            logStreamNamePrefix=lsnp,
            descending=True,
            limit=1,
        )

        if not log_streams["logStreams"]:
            return "No logs found for the container."

        log_stream_name = log_streams["logStreams"][0]["logStreamName"]
        log_stream_arn = log_streams["logStreams"][0]["arn"]
        log_events = client.get_log_events(
            logStreamName=log_stream_name,
            logGroupIdentifier=log_stream_arn,
            limit=25,
            startFromHead=False,
        )

        logs = [event["message"] for event in log_events["events"]]
        str_logs = "\n".join(logs)
        ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
        clean_log = ansi_escape.sub("", str_logs)
        return (
            "```\n"
            + clean_log.replace("    ", "")
            + "\n```"
            + "\n\n"
            + f"CloudWatch Logs Url:\n>{log_url}"
        )
    except Exception as e:
        log.error(f"Error fetching logs: {e}")
        return "Error fetching logs."


# Input: EventBridge Message
# Output: Slack Message


def event_to_slack_message(event):
    event_id = event.get("id")
    detail_type = event.get("detail-type")
    account = event.get("account")
    time = event.get("time")
    region = event.get("region")
    resources = []
    for resource in event["resources"]:
        try:
            resources.append(":dart: " + resource.split(":")[5])
        except Exception:
            log.error("Error parsing the resource ARN: `{}`".format(resource))
            resources.append(":dart: " + resource)
    detail = event.get("detail")
    known_detail = ecs_events_parser(detail_type, detail)
    blocks = []
    contexts = []
    title = f"*{detail_type}*"
    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": title}})
    if resources:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Resources*:\n" + "\n".join(resources),
                },
            }
        )
    if detail and not known_detail:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Event Detail:* ```{json.dumps(detail, indent=4)}```",
                },
            }
        )
    if known_detail:
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": known_detail}}
        )
    contexts.append({"type": "mrkdwn", "text": f"Account: {account} Region: {region}"})
    contexts.append({"type": "mrkdwn", "text": f"Time: {time} UTC Id: {event_id}"})
    blocks.append({"type": "context", "elements": contexts})
    blocks.append({"type": "divider"})
    return {"blocks": blocks}


# Slack web hook example
# https://hooks.slack.com/services/XXXXXXX/XXXXXXX/XXXXXXXXXX
def post_slack_message(hook_url, message):
    headers = {"Content-type": "application/json"}
    connection = http.client.HTTPSConnection("hooks.slack.com")
    connection.request(
        "POST",
        hook_url.replace("https://hooks.slack.com", ""),
        json.dumps(message),
        headers,
    )
    response = connection.getresponse()
    response_body = response.read().decode()
    if response.status != 200:
        raise Exception(f"Slack API error: {response.status} - {response_body}")
    return response.status


# ---------------------------------------------------------------------------------------------------------------------
# LAMBDA HANDLER
# ---------------------------------------------------------------------------------------------------------------------


def lambda_handler(event, context):
    if LOG_EVENTS:
        log.info("Event logging enabled: `{}`".format(json.dumps(event)))

    if event.get("source") != "aws.ecs":
        raise ValueError('The source of the incoming event is not "aws.ecs"')

    slack_message = event_to_slack_message(event)
    response = post_slack_message(SLACK_WEBHOOK_URL, slack_message)
    return json.dumps({"code": response})


# For local testing
if __name__ == "__main__":
    with open("./test/eventbridge_event.json") as f:
        test_event = json.load(f)
    lambda_handler(test_event, "default_context")
