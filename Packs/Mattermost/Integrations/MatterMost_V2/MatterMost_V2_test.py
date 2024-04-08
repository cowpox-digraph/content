import json
from MatterMost_V2 import (get_team_command, list_channels_command, create_channel_command, add_channel_member_command,
                           remove_channel_member_command, list_users_command, close_channel_command, send_file_command,
                           get_channel_id_to_send_notif, event_handler, handle_text_received_from_mm, get_channel_id_from_context,
                           extract_entitlement, answer_question, handle_posts)
import pytest
import demistomock as demisto
from unittest.mock import patch
from freezegun import freeze_time
def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())

def http_mock(method: str, url_suffix: str = "", full_url: str = "", params: dict = {},
              data: dict = {}, files: dict = {}, json_data: dict = {}, headers: dict = {}):

    if 'bot_access_token' in headers.get('authorization', ''):
        if url_suffix == '/api/v4/users/me':
            return util_load_json('test_data/get_bot_response.json')
        if url_suffix == '/api/v4/posts':
            return util_load_json("test_data/create_post_response.json")
    
    if url_suffix == "/api/v4/teams/name/team_name":
        return util_load_json("test_data/get_team_response.json")
    elif url_suffix == '/api/v4/teams/team_id/channels' or url_suffix == '/api/v4/teams/team_id/channels/private':
        return util_load_json("test_data/list_channels_response.json")
    elif url_suffix == '/api/v4/channels':
        return util_load_json("test_data/create_channel_response.json")
    elif url_suffix == '/api/v4/users':
        return util_load_json("test_data/list_users_response.json")
    elif url_suffix == '/api/v4/files':
        return util_load_json("test_data/send_file_response.json")
    elif url_suffix == '/api/v4/users/email/user_email' or url_suffix == '/api/v4/users/username/username' or url_suffix == '/api/v4/users/me':
        return util_load_json("test_data/list_users_response.json")[0]
    elif url_suffix == '/api/v4/channels/direct':
        channel =  util_load_json("test_data/create_channel_response.json")
        channel["type"] = 'D'
        return channel
    else:
        return {}


@pytest.fixture(autouse=True)
def ws_client(mocker):
    from MatterMost_V2 import WebSocketClient

    return WebSocketClient(
        base_url='mock url',
        verify=True,
        proxy=False,
        token='personal_access_token',
    )

@pytest.fixture(autouse=True)
def http_client(mocker):
    from MatterMost_V2 import HTTPClient

    headers = {"Authorization": "Token mock"}
    mocker.patch.object(HTTPClient, "_http_request", side_effect=http_mock)
    return HTTPClient(
        base_url='mock url',
        headers=headers,
        verify=True,
        proxy=False,
        bot_access_token='bot_access_token',
        personal_access_token='personal_access_token',
        team_name='team_name',
        notification_channel='notification_channel',
    )

def test_get_team_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running get_team_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name'}
    results = get_team_command(http_client, args)
    assert results.outputs.get('name', '') == 'team_name'


def test_list_channels_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running list_channels_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'include_private_channels': True}
    results = list_channels_command(http_client, args)
    assert results.outputs[0].get('name') == 'name'
    assert len(results.outputs) == 2


def test_create_channel_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running create_channel_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'name': 'channel_name',
            'display_name': 'display_name',
            'type': 'Public',
            'purpose': 'purpose',
            'header': 'header', }
    results = create_channel_command(http_client, args)
    assert results.outputs.get('name') == 'name'


def test_add_channel_member_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running add_channel_member_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name',
            'user_id': 'user_id', }
    results = add_channel_member_command(http_client, args)
    assert 'The member user_id was added to the channel successfully' in results.readable_output


def test_remove_channel_member_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running remove_channel_member_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name',
            'user_id': 'user_id', }
    results = remove_channel_member_command(http_client, args)
    assert 'The member user_id was removed from the channel successfully.' in results.readable_output


def test_list_users_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running list_users_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_id': 'channel_id', }
    results = list_users_command(http_client, args)
    assert results.outputs[0].get('first_name') == 'first_name'


def test_close_channel_command(http_client):
    """
    Given: A mock MatterMost client.
    When: Running close_channel_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name', }
    results = close_channel_command(http_client, args)
    assert 'The channel channel_name was delete successfully.' in results.readable_output


def test_send_file_command(http_client, mocker):
    """
    Given: A mock MatterMost client.
    When: Running send_file_command with a team name.
    Then: Ensure we get the result.
    """
    expected_file_info = {
        'name': 'test_file.txt',
        'path': '/path/to/test_file.txt'
    }
    mocker.patch('MatterMost_V2.demisto.getFilePath', return_value=expected_file_info)
    mocker.patch.object(http_client, 'send_file_request', return_value=util_load_json("test_data/send_file_response.json"))

    args = {'team_name': 'team_name',
            'channel_name': 'channel_name', }
    send_file_command(http_client, args)


def test_get_channel_id_to_send_notif(http_client, mocker):
    """
    Given: A mock MatterMost client.
    When: Running get_channel_id_to_send_notif.
    Then: Ensure we get the result.
    """
    results = get_channel_id_to_send_notif(http_client, 'username', 'channel_name', 'investigation_id')
    assert results == 'id'

def test_get_channel_id_from_context(mocker):
    """
    Given: A mock MatterMost client.
    When: Running get_channel_id_from_context.
    Then: Ensure we get the result.
    """
    import MatterMost_V2
    MatterMost_V2.CACHE_EXPIRY = False
    MatterMost_V2.CACHED_INTEGRATION_CONTEXT = ''
    mock_integration_context = {
        'mirrors': json.dumps([
            {'channel_name': 'Channel1', 'team_id': 'team_id', 'channel_id': 'ID1',
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
            {'channel_name': 'Channel2', 'team_id': 'team_id', 'channel_id': 'ID2',
             'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
        ])
    }
    mocker.patch('MatterMost_V2.get_integration_context', return_value=mock_integration_context)
    results = get_channel_id_from_context('Channel1', 'Incident123')
    assert results

def test_save_entitlement():
    # Define test inputs
    entitlement = "Test Entitlement"
    message_id = "123"
    reply = "Test Reply"
    expiry = "2023-09-09"
    default_response = "Default Response"
    to_id = "user@example.com"
    SYNC_CONTEXT = True
    OBJECTS_TO_KEYS = {
        'messages': 'entitlement',
    }
    # Mock the required functions (get_integration_context, set_to_integration_context_with_retries) and any other dependencies
    with patch('MatterMost_V2.get_integration_context') as mock_get_integration_context, \
            patch('MatterMost_V2.set_to_integration_context_with_retries') as mock_set_integration_context:

        # Mock the return values of the mocked functions
        mock_get_integration_context.return_value = {'messages': []}
        fixed_timestamp = '2023-09-09T20:08:50Z'

        with freeze_time(fixed_timestamp):
            from MatterMost_V2 import save_entitlement
            # Call the function to be tested
            save_entitlement(entitlement, message_id, reply, expiry, default_response, to_id)

        # Define the expected data to be added to integration context
        expected_data = {
            'messages': [
                {
                    'message_id': message_id,
                    'entitlement': entitlement,
                    'reply': reply,
                    'expiry': expiry,
                    'sent': fixed_timestamp,
                    'default_response': default_response,
                    'to_id': to_id
                }
            ]
        }

        # Assert that the mocked functions were called with the expected arguments
        mock_get_integration_context.assert_called_once_with(SYNC_CONTEXT)
        mock_set_integration_context.assert_called_once_with(expected_data, OBJECTS_TO_KEYS, SYNC_CONTEXT)

@pytest.mark.parametrize("entitlement, expected_result", [
    ("guid123@incident456|task789", ("guid123", "incident456", "task789")),  # Scenario 1: Full entitlement
    ("guid123@incident456", ("guid123", "incident456", "")),  # Scenario 2: No task ID
    ("guid123@", ("guid123", "", "")),  # Scenario 3: No incident ID or task ID
])
def test_extract_entitlement(entitlement, expected_result):
    """
    Test the extract_entitlement function.
    Given:
    - Input entitlement string.
    When:
    - Calling the extract_entitlement function with the given input entitlement.
    Then:
    - Validate that the function correctly extracts the entitlement components: guid, incident_id, and task_id.
    """
    result = extract_entitlement(entitlement)

    # Assert the result against the expected outcome
    assert result == expected_result

def test_handle_posts(mocker):
    """
    Test the extract_entitlement function.
    Given:
    - Input entitlement string.
    When:
    - Calling the extract_entitlement function with the given input entitlement.
    Then:
    - Validate that the function correctly extracts the entitlement components: guid, incident_id, and task_id.
    """
    payload = {}
    
    
######### async tests #########

@pytest.mark.asyncio
async def test_handle_text(mocker):
    # Create mock arguments
    investigation_id = "123"
    text = "Hello, this is a test message"
    operator_email = "test@example.com"
    operator_name = "Test User"
    MESSAGE_FOOTER = '\n**From MatterMost**'

    with patch('MatterMost_V2.demisto') as mock_demisto:
        # Call the function
        await handle_text_received_from_mm(investigation_id, text, operator_email, operator_name)
        # Assert that the `demisto.addEntry` method was called with the expected arguments
        mock_demisto.addEntry.assert_called_once_with(
            id=investigation_id,
            entry=text,
            username=operator_name,
            email=operator_email,
            footer=MESSAGE_FOOTER  # Assuming MESSAGE_FOOTER is defined in your module
        )


# @pytest.mark.asyncio
# async def test_close_channel(client, mocker):
#     """
#     Test the close_channel function
#     Given:
#     - Mocked input parameters.
#     When:
#     - Calling the close_channel function.
#     Then:
#     - Ensure that the function successfully closes the channel.
#     """
#     mock_integration_context = {
#         'mirrors': json.dumps([
#             {'channel_name': 'Channel1', 'channel_jid': 'JID1', 'channel_id': 'ID1',
#              'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
#             {'channel_name': 'Channel2', 'channel_jid': 'JID2', 'channel_id': 'ID2',
#              'investigation_id': 'Incident123', 'mirror_direction': 'both', 'auto_close': True},
#         ])
#     }

#     mocker.patch.object(demisto, 'mirrorInvestigation')
#     mocker.patch.object(Zoom, 'get_integration_context', return_value=mock_integration_context)
#     mocker.patch.object(Zoom, 'set_to_integration_context_with_retries')
#     mocker.patch.object(Zoom, 'get_admin_user_id_from_token', return_value='mock_user_id')
#     mocker.patch.object(Zoom, 'find_mirror_by_investigation', return_value={'channel_id': 'ID1'})

#     from Zoom import close_channel
#     result = close_channel(client)

#     assert result == 'Channel successfully deleted.'


@pytest.mark.asyncio
async def test_event_handler_error(ws_client, mocker):
    error_payload = {"status": "FAIL",
                     "seq_reply": 2,
                     "error": {"id": "some.error.id.here", "message": "Some error message here"
                               }
                    }
    error_mock = mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'updateModuleHealth')

    await event_handler(ws_client, error_payload)

    assert error_mock.call_count == 1
    
@pytest.mark.asyncio
async def test_answer_question(http_client, mocker):
    """
    Test the answer_question function.
    Given:
    - A mocked question dictionary.
    When:
    - Calling the answer_question function with the mocked question.
    Then:
    - Validate that the function correctly handles the entitlement and returns the incident_id.
    """
    MatterMost_V2.CLIENT = http_client
    mock_question = {
        'entitlement': 'guid123@incident456|task789',
        'to_id': '123'
    }
    
    mocker.patch('MatterMost_V2.process_entitlement_reply')

    result = await answer_question("Answer123", mock_question, "user@example.com")
    assert result == 'incident456'