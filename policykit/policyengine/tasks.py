# Create your tasks here
from __future__ import absolute_import, unicode_literals

from celery import shared_task
from celery.schedules import crontab
from policyengine.models import UserVote, NumberVote, BooleanVote, PlatformAction, PlatformActionBundle, Proposal, PlatformPolicy, CommunityUser, ConstitutionAction, ConstitutionPolicy
from policykit.celery import app
from policyengine.views import *

@shared_task
def consider_proposed_actions():
    def _execute_policy(policy, action):

        if filter_policy(policy, action):
            if not policy.has_notified:
                initialize_policy(policy, action)

                check_result = check_policy(policy, action)
                logger.info('checked')
                if check_result == Proposal.PASSED:
                    pass_policy(policy, action)
                    logger.info('passed')
                elif check_result == Proposal.FAILED:
                    logger.info('failed')
                    fail_policy(policy, action)
                else:
                    notify_policy(policy, action)
                    logger.info('notifying')
            else:
                check_result = check_policy(policy, action)
                if check_result == Proposal.PASSED:
                    pass_policy(policy, action)
                    logger.info('passed_two')
                elif check_result == Proposal.FAILED:
                    fail_policy(policy, action)
                    logger.info('failed_two')

    logger.info('reached platform_actions')
    platform_actions = PlatformAction.objects.filter(proposal__status=Proposal.PROPOSED, is_bundled=False)
    for action in platform_actions:
         #if they have execute permission, skip all policies
        if action.initiator.has_perm(action.app_name + '.can_execute_' + action.action_codename):
            action.execute()
        else:
            for policy in PlatformPolicy.objects.filter(community=action.community):
                _execute_policy(policy, action)

    """bundle_actions = PlatformActionBundle.objects.filter(proposal__status=Proposal.PROPOSED)
    for action in bundle_actions:
        #if they have execute permission, skip all policies

        if action.initiator.has_perm(action.app_name + '.can_execute_' + action.action_codename):
            action.execute()
        else:
            for policy in PlatformPolicy.objects.filter(community=action.community):
                _execute_policy(policy, action)"""

    logger.info('reached constitution_actions')
    test_actions = ConstitutionAction.objects.filter(action_codename='policykitaddusserrole', is_bundled=False)
    logger.info(test_actions)
    constitution_actions = ConstitutionAction.objects.filter(proposal__status=Proposal.PROPOSED, is_bundled=False)
    logger.info('just filtered')
    for action in constitution_actions:
        logger.info('in action loop')
        #if they have execute permission, skip all policies
        if action.initiator.has_perm(action.app_name + '.can_execute_' + action.action_codename):
            logger.info('executing')
            action.execute()
        else:
            logger.info('else branch')
            for policy in ConstitutionPolicy.objects.filter(community=action.community):
                logger.info('in policy loop')
                _execute_policy(policy, action)
    logger.info('finished constitution_actions')
