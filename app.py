#!/usr/bin/env python3

import os
import json
import yaml
from urllib.parse import urlencode

from flask import Flask
from flask import redirect
from flask import request
from flask import make_response
from slackclient import SlackClient

EVENT_API_FIELD_TYPE = "X-Gitlab-Token"
EVENT_API_FIELD_TOKEN = "token"
EVENT_API_FIELD_CHALLENGE = "challenge"

EVENT_API_REQ_TYPE_URL_VERIFICATION = "12345678"
EVENT_API_REQ_TYPE_EVENT = "event_callback"

users_list = {}
cfg = yaml.load(open('config.yaml'), Loader=yaml.SafeLoader)

app = Flask(__name__)


class UnsupportedRequestException(BaseException):
    pass

@app.route('/webhook', methods=['POST', 'GET'])
def webhook():
    """Endpoint for event callbacks from slack"""
    req = request.get_json(silent=True, force=True)
    print("Got WebHook Request:", json.dumps(req, indent=4))
    return process_event_api_request(request)

# def handle_errors(func):
#     """Decorator for functions that take single request argument and return dict response."""
#     def error_handling_wrapper(req):
#         try:
#             response = func(req)
#             print("Responding:", response)
#         except UnsupportedRequestException:
#             print("UnsupportedRequestException:", req)
#             response = make_response("Unsupported request %s" % req, 400)
#         except Exception as exc:
#             print("Exception", exc)
#             response = make_response("Unknown error", 500)
#         return response

#     return error_handling_wrapper

def wrap_plain_json(func):
    """Make a proper response object of plain dict/json.
    Wraps function that takes single request argument and return dict response"""
    def json_wrapper(req):
        # main call performed here
        response_body_json = func(req)

        response_body = json.dumps(response_body_json)
        response = make_response(response_body)
        response.headers['Content-Type'] = 'application/json'
        return response

    return json_wrapper

# @handle_errors
@wrap_plain_json
def process_event_api_request(req):
    request_type = req.headers.get(EVENT_API_FIELD_TYPE)
    if request_type == EVENT_API_REQ_TYPE_URL_VERIFICATION:
        return process_handshake_request(req.get_json(silent=True, force=True))
    elif request_type == EVENT_API_REQ_TYPE_EVENT:
        return process_event_request(req)
    else:
        raise UnsupportedRequestException

def process_event_request(req):
    """Process even received request from Slack Events API"""
    message_processor.process_incoming_event(req)
    return {}

def process_event_close_issue(req, SlackMsg):
    SlackMsg['sendto'] = cfg['slack_channel']['close_issue'] or cfg['slack_channel']['default']
    SlackMsg['action'] = req.get('object_attributes', {}).get('action') or ''
    SlackMsg['text'] = '[{project}] *{action}* issue #{issue}: <{issue_url}|{issue_title}>\n'.format(**SlackMsg)

def process_event_reopen_issue(req, SlackMsg):
    SlackMsg['sendto'] = cfg['slack_channel']['reopen_issue'] or cfg['slack_channel']['default']
    SlackMsg['action'] = req.get('object_attributes', {}).get('action') or ''
    SlackMsg['text'] = '[{project}] *{action}* issue #{issue}: <{issue_url}|{issue_title}>\n'.format(**SlackMsg)

def process_event_new_issue(req, SlackMsg):
    SlackMsg['sendto'] = cfg['slack_channel']['new_issue'] or cfg['slack_channel']['default']
    assignes_list = []
    labels_list = []
    if req.get('assignes', None):
        for issues in req['assignees']:
            assignes_list.append(issues['name'])
    if req.get('labels', None):
        for labels in req['labels']:
            labels_list.append(labels['title'])
    SlackMsg['action'] = req.get('object_attributes', {}).get('action') or ''
    SlackMsg['issue_descr'] = req.get('object_attributes', {}).get('description') or ''
    SlackMsg['issue_assignes'] = '|'.join(assignes_list)
    SlackMsg['issue_labels'] = '|'.join(labels_list)
    SlackMsg['text'] = '[{project}] {action} issue #{issue}: <{issue_url}|{issue_title}>\nAssignes: {issue_assignes}\nLabels: {issue_labels}\n>>>{issue_descr}'.format(**SlackMsg)

def process_event_update_issue_assignes(req, SlackMsg):
    SlackMsg['sendto'] = cfg['slack_channel']['update_assignes'] or cfg['slack_channel']['default']
    issue_prev, issue_curr, assignes_list = [], [], []
    for issue_previous in req['changes']['assignees']['previous']:
        issue_prev.append(issue_previous['name'])
    for issue_current in req['changes']['assignees']['current']:
        issue_curr.append(issue_current['name'])
    for issues in req['assignees']:
        assignes_list.append(issues['name'])
    SlackMsg['issue_assignes'] = '|'.join(assignes_list)
    SlackMsg['text'] = '[{project}] Assignees changes on issue #{issue}: <{issue_url}|{issue_title}>\Assigned: {issue_assignes}\n'.format(**SlackMsg)
    if list(set(issue_prev) - set(issue_curr)):
        SlackMsg['text'] += '`Del: {}`\n'.format('|'.join(list(set(issue_prev) - set(issue_curr))))

def process_event_update_issue_labels(req, SlackMsg):
    SlackMsg['sendto'] = cfg['slack_channel']['update_labels'] or cfg['slack_channel']['default']
    labels_prev, labels_current, labels_list = [], [], []
    for issue_labels_previous in req['changes']['labels']['previous']:
        labels_prev.append(issue_labels_previous['title'])
    for issue_labels_current in req['changes']['labels']['current']:
        labels_current.append(issue_labels_current['title'])
    for labels in req['labels']:
        labels_list.append(labels['title'])
    SlackMsg['issue_labels'] = '|'.join(labels_list)
    SlackMsg['text'] = '[{project}]  Labels changes on issue #{issue}: <{issue_url}|{issue_title}>\nLabels: {issue_labels}\n'.format(**SlackMsg)
    if list(set(labels_current) - set(labels_prev)):
        SlackMsg['text'] += '`Add: {}`\n'.format(
                '|'.join(list(set(labels_current) - set(labels_prev)))
            )
    if list(set(labels_prev) - set(labels_current)):
        SlackMsg['text'] += '`Del: {}`\n'.format(
                '|'.join(list(set(labels_prev) - set(labels_current)))
            )

def process_event_new_comment(req, SlackMsg):
    SlackMsg['sendto'] = cfg['slack_channel']['new_comment'] or cfg['slack_channel']['default']
    SlackMsg['issue'] = req.get('object_attributes', {}).get('noteable_id') or ''
    SlackMsg['comment'] = req.get('object_attributes', {}).get('note') or ''
    SlackMsg['issue_title'] =  req.get('issue', {}).get('title') or ''
    SlackMsg['text'] = '[{project}] New comment on issue #{issue}: <{issue_url}|{issue_title}>\n>>>{comment}'.format(**SlackMsg)

def send_to_slack (message='', user='', username='GitLab bot', emoji=':uit:', icon_url='', icon_emoji=':ghost:', override_debug=False):
    sc = SlackClient(cfg['slack_congig']['token'])
    if user == '':
        user='epodshivalov'

    if user[0] == '#':
        sc.api_call(
                "chat.postMessage",
                channel = user,
                text = message,
                username = username,
                icon_url = icon_url,
                icon_emoji = icon_emoji if icon_url == '' else None,
                as_user = 'false',
            )
    else:
        sc_users = sc.api_call('users.list')
        if 'ok' in sc_users:
            for sc_members in sc_users['members']:
                if sc_members['profile']['real_name'] == user:
                    sc_sendtouser = sc_members['id']
                    sc_im = sc.api_call('im.open', user=sc_sendtouser)
                    if 'ok' in sc_im:
                        sc.api_call(
                                "chat.postMessage",
                                channel = sc_im['channel']['id'],
                                text = message,
                                username = username,
                                icon_url = icon_url,
                                icon_emoji = icon_emoji if icon_url == '' else None,
                                as_user = 'false',
                            )
                    sc.api_call('im.close', channel = sc_im['channel']['id'])
                    break

def get_user_id(val):
    keylist = []
    for key, value in users_list.items():
        if val == value['username']:
            keylist.append(key)
    return keylist

def process_handshake_request(req):
    """Process handshake request from Slack Events API"""
    global users_list
    global cfg
    SlackMsg = {}
    current_user = {}
    comment_users_list, slack_users_list = [], []
    SlackMsg['sendto'] = cfg['slack_channel']['default']
    SlackMsg['name'] = req.get('user', {}).get('name') or ''
    SlackMsg['project'] = req.get('project', {}).get('path_with_namespace') or ''
    SlackMsg['issue_url'] = req.get('object_attributes', {}).get('url') or ''
    SlackMsg['issue_title'] = req.get('object_attributes', {}).get('title') or ''
    SlackMsg['icon'] = req.get('user', {}).get('avatar_url') or ':ghost:'
    SlackMsg['issue'] = req.get('object_attributes', {}).get('iid') or req.get('object_attributes', {}).get('noteable_id') or ''

    #Learning gitlab usernames and IDs
    if 'user' in req:
        userid = req.get('user', {}).get('id') or req.get('object_attributes', {}).get('author_id') or 0
        current_user['name'] = req.get('user', {}).get('name') or ''
        current_user['username'] = req.get('user', {}).get('username') or ''
        if current_user['username'] != '':
            if users_list.get(userid, {}):
                users_list[userid]['name'] = current_user['name']
                users_list[userid]['username'] = current_user['username']
            else:
                users_list[userid] = current_user
    ###

    if (req['object_kind'] == 'note') and (req['event_type'] == 'note'):
        process_event_new_comment(req, SlackMsg)
        #Finding users
        if req.get('issue', {}).get('author_id', {}):
            comment_users_list.append(req.get('issue', {}).get('author_id'))
        if req.get('issue', {}).get('assignee_id', {}):
            comment_users_list.append(req.get('issue', {}).get('assignee_id'))
        #Finding assgnee in note
        slack_note = str(req['object_attributes']['note']).replace('\\', '')
        for slack_user in cfg['slack_users']:
            if slack_note.find(slack_user) != -1:
                comment_users_list += get_user_id(slack_user)
        comment_users_list = list(set(comment_users_list))
    elif (req['object_kind'] == 'issue') and (req['event_type'] == 'issue') and (req['object_attributes']['action'] == 'update') and ('labels' in  req['changes']):
        process_event_update_issue_labels(req, SlackMsg)
    elif (req['object_kind'] == 'issue') and (req['event_type'] == 'issue') and (req['object_attributes']['action'] == 'close'):
        process_event_close_issue(req, SlackMsg)
    elif (req['object_kind'] == 'issue') and (req['event_type'] == 'issue') and (req['object_attributes']['action'] == 'reopen'):
        process_event_reopen_issue(req, SlackMsg)
    elif (req['object_kind'] == 'issue') and (req['event_type'] == 'issue') and (req['object_attributes']['action'] == 'update') and ('assignees' in  req['changes']):
        process_event_update_issue_assignes(req, SlackMsg)
    elif (req['object_kind'] == 'issue') and (req['event_type'] == 'issue') and (req['object_attributes']['action'] == 'open'):
        process_event_new_issue(req, SlackMsg)
    else:
        pass

    if SlackMsg.get('text', None):
        if comment_users_list == []:
            slack_users_list.append(SlackMsg['sendto'])
        else:
            for comment_user_id in comment_users_list:
                if comment_user_id in users_list:
                    if users_list[comment_user_id]['username'] in cfg['slack_users']:
                        slack_users_list.append(cfg['slack_users'][users_list[comment_user_id]['username']])
        
        print (slack_users_list)
        for slack_name in slack_users_list:
            if slack_name:
                send_to_slack(message=SlackMsg['text'], user=slack_name, icon_url=SlackMsg['icon'], username=SlackMsg['name'])

    return {"challenge": req.get(EVENT_API_FIELD_CHALLENGE)}

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, port=port, host='0.0.0.0')
