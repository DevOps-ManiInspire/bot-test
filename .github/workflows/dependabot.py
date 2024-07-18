from json import dumps
from datetime import datetime
from logging import info, error, getLogger
from slack_sdk.webhook import WebhookClient
import requests
import pytz
from os import environ, getenv

slackSecret = getenv('WEBHOOK_URL')
gitHubToken = getenv('GITHUBTOKEN')
#gitHubToken = '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'
#slackSecret = 'https://hooks.slack.com/services/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'
channelID = '#monitoring'
repoOwner = 'DevOps-ManiInspire'
repoName = 'bot-test'
vulnerabilityCountToReport = 2

currentTimeUTC = datetime.now(pytz.utc)

logger = getLogger()
logger.setLevel("INFO")
info(f'Repository Scan: {repoOwner}/{repoName}')
info(f"Scan initiated at: {currentTimeUTC.strftime('%Y-%m-%d %H:%M:%S')} UTC")


def send_slack_notification(slackMessageBlock):
    message = {
        "channel": channelID,
        "blocks": slackMessageBlock
    }
    try:
        requests.post(slackSecret, json=message, headers={'Content-Type': 'application/json'})
        info('Slack notification sent successfully!')
    except requests.exceptions.RequestException as e:
        error(f'Error sending Slack notification: {e}')


def getDependabotAlerts():
    url = f'https://api.github.com/repos/{repoOwner}/{repoName}/dependabot/alerts'
    headers = {
        'Authorization': f'Bearer {gitHubToken}',
        'X-GitHub-Api-Version': '2022-11-28'
    }

    try:
        info(f'Retrieving Dependabot alerts for the repository {repoOwner}/{repoName}')
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        vulnerabilityCount = 0
        info(f'Fetching the count of active vulnerabilities {repoOwner}/{repoName}')
        for res in response.json():
            if res['state'] == 'open':
                vulnerabilityCount += 1
        info(f' {vulnerabilityCount} Active Vulnerabilities count within {repoOwner}/{repoName}')
        vulnerabilityTemplateHeader = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"You have *{vulnerabilityCount} Active vulnerabilities* in {repoOwner}/{repoName} \n *NOTE*: Click the button alongside to view the outstanding vulnerabilities"
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Vulnerability List"
                },
                "style": "primary",
                "value": "click_me_123",
                "url": f"https://github.com/{repoOwner}/{repoName}/security/dependabot",
                "action_id": "button-action"
            }
        }
        vulnerabilityTemplateDetailer = {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Scan initiated at*: {currentTimeUTC.strftime('%Y-%m-%d %H:%M')} UTC"
                }
            ]
        }
        slackMessageBlock.append(vulnerabilityTemplateHeader)
        slackMessageBlock.append(vulnerabilityTemplateDetailer)
        info('Fetching active vulnerabilities to generate the report')
        info(f'Generating the report with {vulnerabilityCountToReport} Vulnerabilities as per configuration')
        if vulnerabilityCount >= 1:
            iter = 1
            for res in response.json():
                vulnerabilityData = (f"""*Package Name:* {res["security_vulnerability"]["package"]["name"]}\n*Manifest Path:* {res["dependency"]["manifest_path"]}\n*Vulnerability Version:* {res["security_vulnerability"]["vulnerable_version_range"]}\n*PatchedVersion:* {
                                     res["security_vulnerability"]["first_patched_version"]["identifier"]}\n*CVE ID:* {res["security_advisory"]["cve_id"]}\n*Severity:* {res["security_vulnerability"]["severity"].upper()}\n*Summary:* {res["security_advisory"]["summary"]}""")
                currentVulnerabilityTemplate = {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": vulnerabilityData
                    },
                    "accessory": {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Advisory"
                        },
                        "style": "danger",
                        "value": "click_me_123",
                        "url": "",
                        "action_id": "button-action"
                    }
                }

                if res['state'] == 'open' and iter <= vulnerabilityCountToReport:
                    currentVulnerabilityTemplate['accessory']['url'] = res['security_advisory']['references'][0]['url']
                    slackMessageBlock.append(currentVulnerabilityTemplate)
                    iter += 1

    except requests.exceptions.RequestException as e:
        raise(f'Error: {e}')

    send_slack_notification(dumps(slackMessageBlock))

slackMessageBlock = []
getDependabotAlerts()
