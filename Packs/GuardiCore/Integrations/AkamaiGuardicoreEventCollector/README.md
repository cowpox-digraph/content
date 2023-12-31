This is the Akamai Guardicore event collector integration for XSIAM.
This integration was integrated and tested with version 5.0 of Akamai Guardicore.

## Configure Akamai Guardicore Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for Akamai Guardicore Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://some_url.com) | True |
    | Username | True |
    | Password | True |
    | Max events number per fetch | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### guardicore-get-events

***
Gets events from Akamai Guardicore.

#### Base Command

`guardicore-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Required | 
| from_date | From date to get events from. | Optional | 

#### Context Output

There is no context output for this command.