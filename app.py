#!/usr/bin/env python3

import json
import os

import yaml
from flask import Flask, make_response, request
from slackclient import SlackClient

GITLAB_TOKEN_HEADER = "X-Gitlab-Token"
CONFIG_PATH = os.getenv("CONFIG_PATH", "config.yaml")
DEFAULT_SLACK_USER = os.getenv("DEFAULT_SLACK_USER", "epodshivalov")

users_cache = {}


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as config_file:
            return yaml.safe_load(config_file) or {}
    except FileNotFoundError as exc:
        raise RuntimeError(f"Config file not found: {path}") from exc


cfg = load_config(CONFIG_PATH)

app = Flask(__name__)


def get_slack_config():
    return cfg.get("slack_config") or cfg.get("slack_congig") or {}


def get_slack_token():
    return get_slack_config().get("token", "")


def get_slack_users():
    return cfg.get("slack_users") or {}


def get_channel(*names):
    channels = cfg.get("slack_channel") or {}
    for name in names:
        channel = channels.get(name)
        if channel:
            return channel
    return channels.get("default", "")


def get_gitlab_token():
    gitlab_cfg = cfg.get("gitlab") or {}
    return gitlab_cfg.get("token") or cfg.get("token") or ""


def join_items(items):
    return "|".join(item for item in (items or []) if item)


def extract_assignee_names_from_list(assignees):
    return [assignee.get("name", "") for assignee in (assignees or []) if assignee.get("name")]


def extract_assignee_names(req):
    return extract_assignee_names_from_list(req.get("assignees") or req.get("assignes") or [])


def extract_label_titles_from_list(labels):
    return [label.get("title", "") for label in (labels or []) if label.get("title")]


def extract_label_titles(req):
    return extract_label_titles_from_list(req.get("labels") or [])


def build_base_message(req):
    object_attrs = req.get("object_attributes") or {}
    user = req.get("user") or {}
    return {
        "sendto": get_channel("default"),
        "name": user.get("name", ""),
        "project": (req.get("project") or {}).get("path_with_namespace", ""),
        "issue_url": object_attrs.get("url", ""),
        "issue_title": object_attrs.get("title", ""),
        "icon": user.get("avatar_url") or ":ghost:",
        "issue": object_attrs.get("iid") or object_attrs.get("noteable_id") or "",
    }


def record_user(req):
    user = req.get("user") or {}
    object_attrs = req.get("object_attributes") or {}
    user_id = user.get("id") or object_attrs.get("author_id")
    username = user.get("username") or ""
    if not user_id or not username:
        return
    users_cache[user_id] = {"name": user.get("name", ""), "username": username}


def list_diff(current, previous):
    added = [item for item in current if item not in previous]
    removed = [item for item in previous if item not in current]
    return added, removed


def process_event_close_issue(req, slack_msg):
    slack_msg["sendto"] = get_channel("close_issue")
    slack_msg["action"] = (req.get("object_attributes") or {}).get("action", "")
    slack_msg["text"] = (
        "[{project}] *{action}* issue #{issue}: <{issue_url}|{issue_title}>\n"
    ).format(**slack_msg)


def process_event_reopen_issue(req, slack_msg):
    slack_msg["sendto"] = get_channel("reopen_issue")
    slack_msg["action"] = (req.get("object_attributes") or {}).get("action", "")
    slack_msg["text"] = (
        "[{project}] *{action}* issue #{issue}: <{issue_url}|{issue_title}>\n"
    ).format(**slack_msg)


def process_event_new_issue(req, slack_msg):
    slack_msg["sendto"] = get_channel("new_issue")
    object_attrs = req.get("object_attributes") or {}
    slack_msg["action"] = object_attrs.get("action", "")
    slack_msg["issue_descr"] = object_attrs.get("description") or ""
    slack_msg["issue_assignees"] = join_items(extract_assignee_names(req))
    slack_msg["issue_labels"] = join_items(extract_label_titles(req))
    slack_msg["text"] = (
        "[{project}] {action} issue #{issue}: <{issue_url}|{issue_title}>\n"
        "Assignees: {issue_assignees}\n"
        "Labels: {issue_labels}\n"
        ">>>{issue_descr}"
    ).format(**slack_msg)


def process_event_update_issue_assignees(req, slack_msg):
    slack_msg["sendto"] = get_channel("update_assignees", "update_assignes")
    changes = req.get("changes") or {}
    assignees_change = changes.get("assignees") or {}
    previous = extract_assignee_names_from_list(assignees_change.get("previous"))
    current = extract_assignee_names_from_list(assignees_change.get("current"))
    slack_msg["issue_assignees"] = join_items(extract_assignee_names(req))
    slack_msg["text"] = (
        "[{project}] Assignees changed on issue #{issue}: <{issue_url}|{issue_title}>\n"
        "Assigned: {issue_assignees}\n"
    ).format(**slack_msg)
    added, removed = list_diff(current, previous)
    if added:
        slack_msg["text"] += "`Add: {}`\n".format(join_items(added))
    if removed:
        slack_msg["text"] += "`Del: {}`\n".format(join_items(removed))


def process_event_update_issue_labels(req, slack_msg):
    slack_msg["sendto"] = get_channel("update_labels")
    changes = req.get("changes") or {}
    labels_change = changes.get("labels") or {}
    previous = extract_label_titles_from_list(labels_change.get("previous"))
    current = extract_label_titles_from_list(labels_change.get("current"))
    slack_msg["issue_labels"] = join_items(extract_label_titles(req))
    slack_msg["text"] = (
        "[{project}] Labels changed on issue #{issue}: <{issue_url}|{issue_title}>\n"
        "Labels: {issue_labels}\n"
    ).format(**slack_msg)
    added, removed = list_diff(current, previous)
    if added:
        slack_msg["text"] += "`Add: {}`\n".format(join_items(added))
    if removed:
        slack_msg["text"] += "`Del: {}`\n".format(join_items(removed))


def process_event_new_comment(req, slack_msg):
    slack_msg["sendto"] = get_channel("new_comment")
    object_attrs = req.get("object_attributes") or {}
    issue = req.get("issue") or {}
    slack_msg["issue"] = object_attrs.get("noteable_id") or slack_msg.get("issue", "")
    slack_msg["comment"] = object_attrs.get("note") or ""
    slack_msg["issue_title"] = issue.get("title") or slack_msg.get("issue_title", "")
    slack_msg["text"] = (
        "[{project}] New comment on issue #{issue}: <{issue_url}|{issue_title}>\n"
        ">>>{comment}"
    ).format(**slack_msg)


def send_to_slack(
    message="",
    user="",
    username="GitLab bot",
    emoji=":uit:",
    icon_url="",
    icon_emoji=":ghost:",
    override_debug=False,
):
    slack_token = get_slack_token()
    if not slack_token:
        print("Slack token missing, skipping message")
        return
    user = user or DEFAULT_SLACK_USER
    icon_emoji = icon_emoji or emoji
    slack_client = SlackClient(slack_token)
    icon_emoji_value = icon_emoji if not icon_url else None
    if user.startswith("#"):
        slack_client.api_call(
            "chat.postMessage",
            channel=user,
            text=message,
            username=username,
            icon_url=icon_url,
            icon_emoji=icon_emoji_value,
            as_user=False,
        )
        return

    users_response = slack_client.api_call("users.list")
    if not users_response.get("ok"):
        print("Slack users.list failed:", users_response)
        return
    for member in users_response.get("members", []):
        if member.get("profile", {}).get("real_name") == user:
            user_id = member.get("id")
            if not user_id:
                break
            im_response = slack_client.api_call("im.open", user=user_id)
            if not im_response.get("ok"):
                print("Slack im.open failed:", im_response)
                break
            channel_id = (im_response.get("channel") or {}).get("id")
            if channel_id:
                slack_client.api_call(
                    "chat.postMessage",
                    channel=channel_id,
                    text=message,
                    username=username,
                    icon_url=icon_url,
                    icon_emoji=icon_emoji_value,
                    as_user=False,
                )
                slack_client.api_call("im.close", channel=channel_id)
            break


def get_user_id(val):
    return [key for key, value in users_cache.items() if val == value.get("username")]


def is_note_event(req):
    return req.get("object_kind") == "note" and req.get("event_type") == "note"


def is_issue_event(req, action=None):
    if req.get("object_kind") != "issue" or req.get("event_type") != "issue":
        return False
    if action is None:
        return True
    return (req.get("object_attributes") or {}).get("action") == action


def collect_comment_user_ids(req):
    comment_user_ids = []
    issue = req.get("issue") or {}
    if issue.get("author_id"):
        comment_user_ids.append(issue.get("author_id"))
    if issue.get("assignee_id"):
        comment_user_ids.append(issue.get("assignee_id"))
    slack_note = str((req.get("object_attributes") or {}).get("note", "")).replace("\\", "")
    slack_users = get_slack_users()
    for slack_user in slack_users:
        if slack_user in slack_note:
            comment_user_ids.extend(get_user_id(slack_user))
    return list(set(comment_user_ids))


def resolve_recipients(comment_user_ids, default_channel):
    if not comment_user_ids:
        return [default_channel] if default_channel else []
    slack_users = get_slack_users()
    recipients = []
    seen = set()
    for comment_user_id in comment_user_ids:
        user_info = users_cache.get(comment_user_id)
        if not user_info:
            continue
        username = user_info.get("username")
        if username in slack_users:
            slack_name = slack_users[username]
            if slack_name and slack_name not in seen:
                recipients.append(slack_name)
                seen.add(slack_name)
    return recipients


def process_gitlab_event(req):
    slack_msg = build_base_message(req)
    record_user(req)

    comment_user_ids = []
    if is_note_event(req):
        process_event_new_comment(req, slack_msg)
        comment_user_ids = collect_comment_user_ids(req)
    elif is_issue_event(req, "update") and "labels" in (req.get("changes") or {}):
        process_event_update_issue_labels(req, slack_msg)
    elif is_issue_event(req, "close"):
        process_event_close_issue(req, slack_msg)
    elif is_issue_event(req, "reopen"):
        process_event_reopen_issue(req, slack_msg)
    elif is_issue_event(req, "update") and "assignees" in (req.get("changes") or {}):
        process_event_update_issue_assignees(req, slack_msg)
    elif is_issue_event(req, "open"):
        process_event_new_issue(req, slack_msg)

    if slack_msg.get("text"):
        recipients = resolve_recipients(comment_user_ids, slack_msg.get("sendto", ""))
        print(recipients)
        for slack_name in recipients:
            if slack_name:
                send_to_slack(
                    message=slack_msg["text"],
                    user=slack_name,
                    icon_url=slack_msg["icon"],
                    username=slack_msg["name"],
                )

    if req.get("challenge"):
        return {"challenge": req.get("challenge")}
    return {"ok": True}


def process_handshake_request(req):
    return process_gitlab_event(req)


def wrap_plain_json(func):
    """Make a proper response object of plain dict/json.
    Wraps function that returns dict response."""

    def json_wrapper(*args, **kwargs):
        response_body = func(*args, **kwargs)
        if isinstance(response_body, tuple):
            response_body, status_code = response_body
        else:
            status_code = 200
        response = make_response(json.dumps(response_body), status_code)
        response.headers["Content-Type"] = "application/json"
        return response

    return json_wrapper


@wrap_plain_json
def process_event_api_request(req, payload=None):
    if req.method == "GET":
        return {"ok": True}
    if payload is None:
        payload = req.get_json(silent=True, force=True)
    if not payload or not isinstance(payload, dict):
        return {"error": "Invalid JSON payload"}, 400
    expected_token = get_gitlab_token()
    if expected_token:
        provided_token = req.headers.get(GITLAB_TOKEN_HEADER, "")
        if provided_token != expected_token:
            return {"error": "Invalid token"}, 403
    try:
        return process_gitlab_event(payload)
    except Exception as exc:
        print("Exception", exc)
        return {"error": "Internal error"}, 500


@app.route("/webhook", methods=["POST", "GET"])
def webhook():
    """Endpoint for event callbacks from GitLab."""
    payload = request.get_json(silent=True, force=True)
    print("Got WebHook Request:", json.dumps(payload, indent=4))
    return process_event_api_request(request, payload)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, port=port, host="0.0.0.0")
