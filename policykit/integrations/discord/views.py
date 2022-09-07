import socketio
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth import login, authenticate
from django.views.decorators.csrf import csrf_exempt
from policykit.settings import SERVER_URL, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN, ALLOWED_CHANNELS
from policyengine.models import *
from integrations.discord.models import *
from urllib import parse
import urllib.request
import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# standard Python
sio = socketio.Client()

sio.connect('http://localhost:8299')


# Used for Boolean voting
# EMOJI_LIKE = ['👍', '👍🏻', '👍🏼', '👍🏽', '👍🏾', '👍🏿']
EMOJI_LIKE = '👍'
# EMOJI_DISLIKE = ['👎', '👎🏻', '👎🏼', '👎🏽', '👎🏾', '👎🏿']
EMOJI_DISLIKE = '👎'


GATEWAY_VERSION = 9

session_id = None
heartbeat_interval = None
ack_received = True
sequence_number = None


def should_create_action(message, type=None):
    if type == None:
        logger.error('type parameter not specified in should_create_action')
        return False

    if not str(message["channel_id"]) in ALLOWED_CHANNELS and not message["is_proposal_thread"]:
        logger.debug("ignoring message")
        return

    created_at = None

    if type == "MESSAGE_CREATE":
        # If message already has an object, don't create a new object for it.
        # We only filter on message IDs because they are generated using Twitter
        # snowflakes which are universally unique across all Discord servers.
        if DiscordPostMessage.objects.filter(message_id=message['id']).exists():
            return False

        created_at = message['timestamp']  # ISO8601 timestamp
        created_at = datetime.strptime(
            created_at, "%Y-%m-%dT%H:%M:%S.%f+00:00")

    if created_at == None:
        logger.error(
            "created_at is None when it shouldn't be in should_create_action")
        return False

    now = datetime.now()

    # If action is more than twice the Celery beat frequency seconds old,
    # don't create an object for it. This way, we only create objects for
    # actions taken after PolicyKit has been installed to the community.
    recent_time = 2 * settings.CELERY_BEAT_FREQUENCY
    if now - created_at > timedelta(seconds=recent_time):
        return False
    return True


def handle_guild_create_event(data):
    # Populate the DiscordChannel objects
    for channel in data['channels']:
        c = DiscordChannel.objects.filter(channel_id=channel['id'])
        if c.exists():
            c = c[0]
            c.channel_name = channel['name']
            c.save()
        else:
            c = DiscordChannel.objects.create(
                guild_id=data['id'],
                channel_id=channel['id'],
                channel_name=channel['name']
            )
    logger.info(f'Populated DiscordChannel objects from GUILD_CREATE event')


def handle_thread_channel(data):
    channel = DiscordChannel.objects.filter(
        channel_id=data['channel_id'])
    if not len(channel):
        DiscordChannel.objects.create(
            guild_id=data['guild_id'],
            channel_id=data['channel_id'],
            channel_name=data['proposal_name']
        )


def handle_message_create_event(data):
    proposal = PolicykitAddCommunityDoc.objects.filter(
        data__data_store__contains=data["channel_id"], proposal__status="proposed")
    is_proposal_thread = proposal.exists()

    if is_proposal_thread and proposal:
        proposal = proposal[0]
        data["is_proposal_thread"] = is_proposal_thread
        data["proposal_name"] = proposal.name

    if should_create_action(data, type="MESSAGE_CREATE"):
        if data["is_proposal_thread"]:
            handle_thread_channel(data)
        channel = DiscordChannel.objects.filter(
            channel_id=data['channel_id'])[0]
        guild_id = channel.guild_id
        community = DiscordCommunity.objects.filter(team_id=guild_id)[0]

        action = DiscordPostMessage()
        action.community = community
        action.text = data['content']
        action.channel_id = data['channel_id']
        action.message_id = data['id']

        u, _ = DiscordUser.objects.get_or_create(
            username=f"{data['author']['id']}:{guild_id}",
            community=community
        )
        action.initiator = u

        logger.info(
            f'New message in channel {channel.channel_name}: {data["content"]}')

        return action


def handle_message_delete_event(data):
    channel = DiscordChannel.objects.filter(channel_id=data['channel_id'])[0]
    guild_id = channel.guild_id
    community = DiscordCommunity.objects.filter(team_id=guild_id)[0]

    # Gets the channel message
    # This doesn't work, it always returns 404. The message has already been deleted.
    # There is no way to retrieve deleted messages in Discord
    message = community.make_call(
        f"channels/{data['channel_id']}/messages/{data['id']}")

    action = DiscordDeleteMessage()
    action.community = community
    action.channel_id = data['channel_id']
    action.message_id = data['id']

    u, _ = DiscordUser.objects.get_or_create(
        username=f"{message['author']['id']}:{guild_id}",
        community=community
    )
    action.initiator = u

    logger.info(
        f'Message deleted in channel {channel.channel_name}: {message["content"]}')

    return action


def handle_channel_update_event(data):
    guild_id = data['guild_id']
    community = DiscordCommunity.objects.filter(team_id=guild_id)[0]

    action = DiscordRenameChannel()
    # FIXME: name_old is not stored, so the action cannot be reverted.
    action.community = community
    action.channel_id = data['id']
    action.name = data['name']

    # FIXME: User who changed channel name not passed along with CHANNEL_UPDATE
    # event. All PlatformActions require an initiator in PolicyKit, so as a
    # placeholder, the Discord client ID is set as the initiator.
    # However, this is not accurate and should be changed in the future
    # if and when possible.
    u, _ = DiscordUser.objects.get_or_create(
        username=f"{DISCORD_CLIENT_ID}:{guild_id}",
        community=community
    )
    action.initiator = u

    channel = DiscordChannel.objects.filter(channel_id=data['id'])[0]
    logger.info(
        f'Channel {channel.channel_name} renamed to {action.name}'.encode('utf-8'))

    # Update DiscordChannel object
    channel.channel_name = action.name
    channel.save()

    return action


def handle_channel_create_event(data):
    guild_id = data['guild_id']
    community = DiscordCommunity.objects.filter(team_id=guild_id)[0]

    # Create new DiscordChannel object
    DiscordChannel.objects.get_or_create(
        guild_id=guild_id,
        channel_id=data['id'],
        channel_name=data['name']
    )

    action = DiscordCreateChannel()
    action.community = community
    action.guild_id = guild_id
    action.name = data['name']

    # FIXME: Same issue as in handle_channel_update_event()
    u, _ = DiscordUser.objects.get_or_create(
        username=f"{DISCORD_CLIENT_ID}:{guild_id}",
        community=community
    )
    action.initiator = u

    logger.info(f'Channel created: {action.name}')

    return action


def handle_channel_delete_event(data):
    guild_id = data['guild_id']
    community = DiscordCommunity.objects.filter(team_id=guild_id)[0]

    action = DiscordDeleteChannel()
    action.community = community
    action.channel_id = data['id']

    # FIXME: Same issue as in handle_channel_update_event()
    u, _ = DiscordUser.objects.get_or_create(
        username=f"{DISCORD_CLIENT_ID}:{guild_id}",
        community=community
    )
    action.initiator = u

    logger.info(f'Channel deleted: {data["name"]}')

    return action


@sio.on("*")
def handle_event(name, data):
    if name == 'READY':
        handle_ready_event(data)
    elif name == 'GUILD_CREATE':
        handle_guild_create_event(data)
    else:
        action = None

        if name == 'MESSAGE_CREATE':
            action = handle_message_create_event(data)
        # elif name == 'MESSAGE_DELETE':
        #     action = handle_message_delete_event(data)
        elif name == 'CHANNEL_UPDATE':
            action = handle_channel_update_event(data)
        elif name == 'CHANNEL_CREATE':
            action = handle_channel_create_event(data)
        elif name == 'CHANNEL_DELETE':
            action = handle_channel_delete_event(data)

        if action:
            action.community_origin = True
            action.is_bundled = False
            action.save()

            # While consider_proposed_actions will execute every Celery beat,
            # we don't want to wait for the beat since using websockets we can
            # know right away when an event is triggered in Discord. Thus, we
            # manually call consider_proposed_actions whenever we have a new
            # proposed action in Discord.
            # from policyengine.tasks import consider_proposed_actions
            # consider_proposed_actions()

        if name == 'MESSAGE_REACTION_ADD':
            action_res = PlatformAction.objects.filter(
                community_post=data['message_id'])
            action_res = action_res or ConstitutionAction.objects.filter(
                community_post=data['message_id'])
            # logger.debug(action_res.get())
            if action_res.exists():
                action = action_res[0]
                reaction = data['emoji']['name']
                if reaction in [EMOJI_LIKE, EMOJI_DISLIKE]:
                    val = (reaction == EMOJI_LIKE)
                    user = DiscordUser.objects.get(username=f"{data['user_id']}:{data['guild_id']}",
                                                   community=action.community)
                    vote = BooleanVote.objects.filter(
                        proposal=action.proposal, user=user)

                    if vote.exists():
                        vote = vote[0]
                        vote.boolean_value = val
                        vote.save()

                    else:
                        vote = BooleanVote.objects.create(proposal=action.proposal,
                                                          user=user,
                                                          boolean_value=val)


def oauth(request):
    state = request.GET.get('state')
    code = request.GET.get('code')
    guild_id = request.GET.get('guild_id')
    error = request.GET.get('error')

    if error == 'access_denied':
        return redirect('/login?error=sign_in_failed')

    data = parse.urlencode({
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': SERVER_URL + '/discord/oauth'
    }).encode()

    req = urllib.request.Request(
        'https://discord.com/api/oauth2/token', data=data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0")
    resp = urllib.request.urlopen(req)
    res = json.loads(resp.read().decode('utf-8'))

    if state == 'policykit_discord_user_login':
        access_token = res['access_token']

        req = urllib.request.Request(
            'https://discord.com/api/users/@me/guilds')
        req.add_header('Authorization', 'Bearer %s' % access_token)
        req.add_header("User-Agent", "Mozilla/5.0")
        resp = urllib.request.urlopen(req)
        guilds = json.loads(resp.read().decode('utf-8'))

        integrated_guilds = []
        for g in guilds:
            s = DiscordCommunity.objects.filter(team_id=g['id'])
            if s.exists():
                integrated_guilds.append((g['id'], g['name']))

        if len(integrated_guilds) == 0:
            return redirect('/login?error=no_policykit_integrated_guilds_found')
        elif len(integrated_guilds) == 1:
            return auth(request, guild_id=integrated_guilds[0][0], access_token=access_token)
        else:
            # If user has more than one PK-integrated Discord guild, bring user to screen to select which guild's dashboard to login to
            return render(request, "policyadmin/configure_discord.html", {"integrated_guilds": integrated_guilds, "access_token": access_token})

    elif state == 'policykit_discord_mod_install':
        req = urllib.request.Request(
            'https://discord.com/api/guilds/%s' % guild_id)
        req.add_header("Content-Type", "application/json")
        req.add_header('Authorization', 'Bot %s' % DISCORD_BOT_TOKEN)
        req.add_header("User-Agent", "DiscordBot ($url, $versionNumber)")
        resp = urllib.request.urlopen(req)
        guild_info = json.loads(resp.read().decode('utf-8'))

        s = DiscordCommunity.objects.filter(team_id=guild_id)
        community = None
        user_group, _ = CommunityRole.objects.get_or_create(
            role_name="Base User", name="Discord: " + guild_info['name'] + ": Base User")

        if not s.exists():
            parent_community = Community.objects.create(
                readable_name=guild_info['name'])
            community = DiscordCommunity.objects.create(
                community_name=guild_info['name'],
                community=parent_community,
                team_id=guild_id,
                base_role=user_group
            )
            user_group.community = community
            user_group.save()
            done_downloading = False
            guild_members = []
            limit = 1000
            after = "0"
            # Get the list of users and create a DiscordUser object for each user
            while not done_downloading:
                result = community.make_call(
                    f'guilds/{guild_id}/members?after={after}&limit={1000}')
                guild_members = guild_members + result
                after = guild_members[-1]['user']['id']
                done_downloading = len(result) < limit
            owner_id = guild_info['owner_id']
            for member in guild_members:
                user, _ = DiscordUser.objects.get_or_create(
                    username=f"{member['user']['id']}:{guild_id}",
                    readable_name=member['user']['username'],
                    avatar=member['user'][
                        'avatar'] and f"https://cdn.discordapp.com/avatars/{member['user']['id']}/{member['user']['avatar']}.png",
                    community=community,
                    is_community_admin=(member['user']['id'] == owner_id)
                )
                user.save()
        else:
            community = s[0]
            community.community_name = guild_info['name']
            community.team_id = guild_id
            community.save()

            return redirect('/login?success=true')

        context = {
            "starterkits": [kit.name for kit in DiscordStarterKit.objects.all()],
            "community_name": community.community_name,
            "platform": "discord"
        }
        return render(request, "policyadmin/init_starterkit.html", context)

    return redirect('/login?error=no_owned_guilds_found')


@csrf_exempt
def auth(request, guild_id=None, access_token=None):
    if not guild_id:  # Redirected from Configure page
        guild_id = request.POST['guild_id']
        if not guild_id:
            return redirect('/login?error=guild_id_missing')

    if not access_token:  # Redirected from Configure page
        access_token = request.POST['access_token']
        if not access_token:
            return redirect('/login?error=access_token_missing')

    user = authenticate(request, guild_id=guild_id, access_token=access_token)
    if user:
        login(request, user)
        return redirect('/main')
    else:
        return redirect('/login?error=invalid_login')


def initiate_action_vote(policy, action, users=None, template=None, channel=None):
    message = "This action is governed by the following policy: " + policy.name
    if template:
        message = template

    # User can input either channel_id or channel_name as channel parameter.
    # Here, we must check whether the user entered a valid channel_id. If not,
    # we check if the user entered a valid channel_name.
    channel_id = None
    c = None
    try:
        c = DiscordChannel.objects.filter(channel_id=channel)
    except:
        pass
    if c and c.exists():
        channel_id = c[0].channel_id
    else:
        c = DiscordChannel.objects.filter(
            guild_id=policy.community.team_id, channel_name=channel)
        if c.exists():
            channel_id = c[0].channel_id
    if channel_id == None:
        return

    res = policy.community.post_message(text=message, channel=channel_id)

    if action.action_type == "ConstitutionAction" or action.action_type == "PlatformAction":
        action.community_post = res['id']
        action.save()


def react_to_message(community: DiscordCommunity, channel, message_id, reaction):
    channel_id = None
    c = None
    try:
        c = DiscordChannel.objects.filter(channel_id=channel)
    except:
        pass
    if c and c.exists():
        channel_id = c[0].channel_id
    else:
        c = DiscordChannel.objects.filter(
            guild_id=community.team_id, channel_name=channel)
        if c.exists():
            channel_id = c[0].channel_id
    if channel_id == None:
        return
    reaction_code = str(reaction.encode('utf-8')) \
        .replace("\\x", "%") \
        .replace('b\'', '') \
        .replace("'", "") \
        .upper()
    community.make_call(
        f'channels/{channel_id}/messages/{message_id}/reactions/{reaction_code}/@me', method="PUT")
