"""Offline regression tests. AWS SDK imports and clients are replaced with mocks.
Run from the package root: python -m unittest discover -s tests -v
No AWS account, credentials, SDK installation or network access is required.
"""
import importlib.util
import json
import logging
import os
from pathlib import Path
import sys
import time
import types
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'lambda' / 'src' / 'remediate.py'
POLICY = 'arn:aws:iam::aws:policy/AdministratorAccess'

class FakeClientError(Exception):
    def __init__(self, response, operation='test'):
        self.response = response
        super().__init__(f'{operation}: {response}')

class FakeBotoCoreError(Exception):
    pass

class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.iam = MagicMock()
        self.sns = MagicMock()
        self.sns.publish.return_value = {'MessageId': 'offline-message'}
        self.securityhub = MagicMock()
        self.securityhub.batch_import_findings.return_value = {
            'SuccessCount': 1, 'FailedCount': 0, 'FailedFindings': []
        }
        self.table = MagicMock()
        self.table.get_item.return_value = {}

        self.ledger = MagicMock()
        self.ledger.get_item.return_value = {}

        self.db = MagicMock()
        self.db.Table.side_effect = lambda name: {
            'test-exceptions': self.table,
            'test-actions': self.ledger,
        }[name]
        boto = types.ModuleType('boto3')
        boto.client = lambda service, **kwargs: {
            'iam': self.iam,
            'sns': self.sns,
            'securityhub': self.securityhub,
        }[service]
        boto.resource = lambda service, **kwargs: self.db
        core = types.ModuleType('botocore')
        errors = types.ModuleType('botocore.exceptions')
        errors.ClientError = FakeClientError
        errors.BotoCoreError = FakeBotoCoreError
        self.env = patch.dict(os.environ, {
            'DRY_RUN': 'true', 'EXCEPTION_TABLE_NAME': 'test-exceptions',
            'LIVE_REMEDIATION_USER': 'iam-test-user',
            'EXCEPTION_TABLE_REGION': 'us-east-1',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-alerts',
            'SECURITY_HUB_ENABLED': 'true',
            'SECURITY_HUB_REGION': 'us-east-1',
            'ACTION_LEDGER_TABLE_NAME': 'test-actions',
            'ACTION_LEDGER_TABLE_REGION': 'us-east-1',
        })
        self.env.start(); self.addCleanup(self.env.stop)
        self.sdk = patch.dict(sys.modules, {
            'boto3': boto, 'botocore': core, 'botocore.exceptions': errors,
        })
        self.sdk.start(); self.addCleanup(self.sdk.stop)
        self.module_patch = patch.dict(sys.modules)
        self.module_patch.start(); self.addCleanup(self.module_patch.stop)
        self.m = self.load()
        # Expected error-path logs do not clutter the offline test summary.
        self.old_disabled = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, self.old_disabled)

    def load(self):
        spec = importlib.util.spec_from_file_location('remediate_offline', SOURCE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def event(self, actor='operator', target='iam-test-user', policy=POLICY):
        return {'id': 'eventbridge-event-test-1', 'detail': {
            'eventName': 'AttachUserPolicy', 'eventSource': 'iam.amazonaws.com',
            'eventID': 'cloudtrail-event-test-1',
            'eventTime': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time())),
            'userIdentity': {'arn': 'arn:aws:iam::123456789012:user/' + actor},
            'requestParameters': {'userName': target, 'policyArn': policy},
            'recipientAccountId': '123456789012',
        }}

    def record(self, **overrides):
        item = {'pk': 'RESOURCE#iam-test-user',
                'sk': 'CONTROL#IAM_ADMIN_POLICY_ATTACHMENT',
                'status': 'APPROVED', 'expires_at_epoch': Decimal(int(time.time()) + 3600),
                'ticket_id': 'SEC-123', 'approved_by': 'reviewer'}
        item.update(overrides)
        self.table.get_item.return_value = {'Item': item}
        return item

    def decision(self, event=None):
        return self.m.evaluate((event or self.event())['detail'])

    def handle(self, event=None):
        return json.loads(self.m.lambda_handler(event or self.event(), None)['body'])

    def test_self_attachment_no_longer_bypasses(self):
        self.assertEqual(self.decision(self.event(actor='iam-test-user')).action, 'REMEDIATE')

    def test_self_attachment_can_use_valid_approval(self):
        self.record()
        self.assertEqual(self.decision(self.event(actor='iam-test-user')).action, 'SKIP_APPROVED')

    def test_outside_scope_does_not_read_or_mutate(self):
        for target in ['production-user', 'iam-test-', 'prefix-iam-test-user', 'iam-test-user/other']:
            with self.subTest(target=target):
                self.assertEqual(self.decision(self.event(target=target)).action, 'NO_ACTION')
        self.table.get_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_protected_user_is_preserved(self):
        self.m.PROTECTED_USERS.add('iam-test-protected')
        self.assertEqual(self.decision(self.event(target='iam-test-protected')).action, 'NO_ACTION')
        self.table.get_item.assert_not_called()

    def test_non_dangerous_policy_is_ignored(self):
        self.assertEqual(self.decision(self.event(policy='arn:aws:iam::aws:policy/ReadOnlyAccess')).action, 'NO_ACTION')
        self.table.get_item.assert_not_called()

    def test_failed_api_call_does_not_trigger_detach(self):
        event = self.event(); event['detail']['errorCode'] = 'AccessDenied'
        self.assertEqual(self.decision(event).action, 'NO_ACTION')
        self.table.get_item.assert_not_called()

    def test_missing_target_and_unsupported_event(self):
        event = self.event(); event['detail']['requestParameters'].pop('userName')
        self.assertEqual(self.decision(event).action, 'NO_ACTION')
        event['detail']['eventName'] = 'Unsupported'
        self.assertEqual(self.decision(event).action, 'NO_ACTION')

    def test_no_record_remediates_in_dry_run_only(self):
        body = self.handle()
        self.assertEqual(body['decision'], 'REMEDIATE')
        self.assertEqual(body['remediation_result']['status'], 'dry_run')
        self.sns.publish.assert_called_once()
        self.iam.detach_user_policy.assert_not_called()

    def test_approved_record_skips_and_retains_metadata(self):
        self.record()
        body = self.handle()
        self.assertEqual(body['decision'], 'SKIP_APPROVED')
        payload = json.loads(self.sns.publish.call_args.kwargs['Message'])
        self.assertEqual(payload['exception_ticket_id'], 'SEC-123')
        self.iam.detach_user_policy.assert_not_called()

    def test_actionable_detection_imports_minimum_asff_finding(self):
        body = self.handle()
        self.assertEqual(body['security_hub_result']['status'], 'success')
        finding = self.securityhub.batch_import_findings.call_args.kwargs['Findings'][0]
        product_arn = (
            'arn:aws:securityhub:us-east-1:123456789012:'
            'product/123456789012/default'
        )
        self.assertEqual(finding['SchemaVersion'], '2018-10-08')
        self.assertEqual(finding['ProductArn'], product_arn)
        self.assertEqual(
            finding['Id'],
            product_arn + '/cloud-security-automation/cloudtrail-event-test-1',
        )
        self.assertEqual(finding['AwsAccountId'], '123456789012')
        self.assertEqual(finding['GeneratorId'], 'IAM_ADMIN_POLICY_ATTACHMENT')
        self.assertEqual(finding['Severity']['Label'], 'HIGH')
        self.assertEqual(finding['Types'], ['TTPs/Privilege Escalation'])
        self.assertEqual(finding['FindingProviderFields']['Severity']['Label'], 'HIGH')
        self.assertEqual(finding['Resources'][0]['Type'], 'AwsIamUser')
        self.assertEqual(
            finding['Resources'][0]['Id'],
            'arn:aws:iam::123456789012:user/iam-test-user',
        )
        self.assertNotIn('Region', finding['Resources'][0])
        self.assertEqual(finding['ProductFields']['governance-decision'], 'REMEDIATE')
        self.assertEqual(finding['ProductFields']['dry-run'], 'true')
        self.assertNotIn('exception_ticket_id', json.dumps(finding))
        self.assertNotIn('exception_approved_by', json.dumps(finding))

    def test_attach_self_fixture_can_publish_security_hub_finding(self):
        fixture = SOURCE.parents[2] / 'tests' / 'fixtures' / 'attach-self.json'
        event = json.loads(fixture.read_text())
        body = self.handle(event)

        self.assertEqual(body['decision'], 'REMEDIATE')
        self.assertEqual(body['security_hub_result']['status'], 'success')
        self.assertEqual(body['remediation_result']['status'], 'dry_run')
        self.securityhub.batch_import_findings.assert_called_once()

    def test_repeated_event_uses_stable_finding_id(self):
        event = self.event()
        self.handle(event)
        first = self.securityhub.batch_import_findings.call_args.kwargs['Findings'][0]['Id']
        self.handle(event)
        second = self.securityhub.batch_import_findings.call_args.kwargs['Findings'][0]['Id']
        self.assertEqual(first, second)

    def test_approved_exception_is_reported_without_sensitive_metadata(self):
        self.record()
        body = self.handle()
        self.assertEqual(body['decision'], 'SKIP_APPROVED')
        finding = self.securityhub.batch_import_findings.call_args.kwargs['Findings'][0]
        self.assertEqual(
            finding['FindingProviderFields']['Severity']['Label'], 'INFORMATIONAL'
        )
        self.assertEqual(finding['ProductFields']['governance-decision'], 'SKIP_APPROVED')
        serialized = json.dumps(finding)
        self.assertNotIn('SEC-123', serialized)
        self.assertNotIn('reviewer', serialized)

    def test_no_action_does_not_create_security_hub_finding(self):
        self.handle(self.event(policy='arn:aws:iam::aws:policy/ReadOnlyAccess'))
        self.securityhub.batch_import_findings.assert_not_called()

    def test_partial_import_failure_is_visible_but_does_not_change_decision(self):
        self.securityhub.batch_import_findings.return_value = {
            'SuccessCount': 0,
            'FailedCount': 1,
            'FailedFindings': [{
                'Id': 'test-id', 'ErrorCode': 'InvalidInput',
                'ErrorMessage': 'invalid finding',
            }],
        }
        body = self.handle()
        self.assertEqual(body['decision'], 'REMEDIATE')
        self.assertEqual(body['remediation_result']['status'], 'dry_run')
        self.assertEqual(body['security_hub_result']['status'], 'error')
        self.iam.detach_user_policy.assert_not_called()

    def test_security_hub_sdk_failure_is_non_blocking(self):
        self.securityhub.batch_import_findings.side_effect = FakeClientError(
            {'Error': {'Code': 'AccessDeniedException'}}
        )
        body = self.handle()
        self.assertEqual(body['decision'], 'REMEDIATE')
        self.assertEqual(body['security_hub_result']['status'], 'error')
        self.assertEqual(body['remediation_result']['status'], 'dry_run')

    def test_security_hub_feature_flag_skips_publish(self):
        self.m.SECURITY_HUB_ENABLED = False
        body = self.handle()
        self.assertEqual(body['security_hub_result']['status'], 'skipped')
        self.securityhub.batch_import_findings.assert_not_called()

    def test_expired_pending_revoked_records_do_not_approve(self):
        for overrides in [{'expires_at_epoch': 0}, {'status': 'PENDING'}, {'status': 'REVOKED'}]:
            with self.subTest(overrides=overrides):
                self.record(**overrides)
                self.assertEqual(self.decision().action, 'REMEDIATE')

    def test_expiry_boundary_is_expired(self):
        self.record(expires_at_epoch=100)
        with patch.object(self.m.time, 'time', return_value=100):
            self.assertEqual(self.decision().action, 'REMEDIATE')

    def test_malformed_expiry_still_alerts_without_iam_mutation(self):
        for expiry in [None, 'invalid', True, Decimal('1.5'), 'NaN', 'Infinity', [], {}, 1.5]:
            with self.subTest(expiry=expiry):
                self.record(expires_at_epoch=expiry)
                self.sns.reset_mock()
                body = self.handle()
                self.assertEqual(body['decision'], 'REMEDIATE')
                self.assertIn('Malformed', body['reason'])
                self.sns.publish.assert_called_once()
        self.iam.detach_user_policy.assert_not_called()

    def test_missing_expiry_is_invalid(self):
        item = self.record(); item.pop('expires_at_epoch')
        self.assertEqual(self.decision().action, 'REMEDIATE')

    def test_wrong_resource_or_control_never_approves(self):
        for changes in [{'pk': 'RESOURCE#other'}, {'sk': 'CONTROL#OTHER'}]:
            with self.subTest(changes=changes):
                self.record(**changes)
                self.assertEqual(self.decision().action, 'REMEDIATE')

    def test_malformed_item_does_not_crash(self):
        for item in [[], 'invalid', {}]:
            with self.subTest(item=item):
                self.table.get_item.return_value = {'Item': item}
                self.assertEqual(self.decision().action, 'REMEDIATE')

    def test_reads_are_strongly_consistent(self):
        self.decision()
        self.table.get_item.assert_called_once_with(
            Key={'pk': 'RESOURCE#iam-test-user', 'sk': 'CONTROL#IAM_ADMIN_POLICY_ATTACHMENT'},
            ConsistentRead=True)

    def test_client_lookup_failure_notifies_then_raises_no_mutation(self):
        self.m.DRY_RUN = False
        self.table.get_item.side_effect = FakeClientError({'Error': {'Code': 'AccessDeniedException'}})
        with self.assertRaisesRegex(RuntimeError, 'Exception lookup unavailable'):
            self.handle()
        self.sns.publish.assert_called_once()
        self.iam.detach_user_policy.assert_not_called()

    def test_network_lookup_failure_notifies_then_raises(self):
        self.table.get_item.side_effect = FakeBotoCoreError('endpoint unavailable')
        with self.assertRaisesRegex(RuntimeError, 'Exception lookup unavailable'):
            self.handle()
        self.sns.publish.assert_called_once()

    def test_missing_table_configuration_notifies_then_raises(self):
        self.m.EXCEPTION_TABLE_NAME = ''
        with self.assertRaisesRegex(RuntimeError, 'Exception lookup unavailable'):
            self.handle()
        self.sns.publish.assert_called_once()
        self.table.get_item.assert_not_called()

    def test_sns_error_raises_before_mutation(self):
        self.m.DRY_RUN = False
        self.sns.publish.side_effect = FakeClientError({'Error': {'Code': 'KMSAccessDenied'}})
        with self.assertRaisesRegex(RuntimeError, 'SNS notification failed'):
            self.handle()
        self.iam.detach_user_policy.assert_not_called()

    def test_sns_transport_failure_raises_before_mutation(self):
        self.m.DRY_RUN = False
        self.sns.publish.side_effect = FakeBotoCoreError('timeout')
        with self.assertRaises(FakeBotoCoreError):
            self.handle()
        self.iam.detach_user_policy.assert_not_called()

    def test_missing_sns_configuration_is_failure(self):
        self.m.SNS_TOPIC_ARN = ''
        with self.assertRaisesRegex(RuntimeError, 'SNS notification failed'):
            self.handle()

    def test_missing_or_blank_live_target_blocks_mutation(self):
        for setting in (None, '', '   '):
            with self.subTest(setting=setting), patch.dict(os.environ, {'DRY_RUN': 'false'}):
                if setting is None:
                    os.environ.pop('LIVE_REMEDIATION_USER', None)
                else:
                    os.environ['LIVE_REMEDIATION_USER'] = setting

                module = self.load()
                body = json.loads(module.lambda_handler(self.event(), None)['body'])

                self.assertEqual(body['decision'], 'REMEDIATE')
                self.assertEqual(body['remediation_result']['status'], 'blocked')
                self.iam.detach_user_policy.assert_not_called()

    def test_live_target_requires_exact_username_match(self):
        self.m.DRY_RUN = False
        for target in ('iam-test-user-extra', 'iam-test-other'):
            with self.subTest(target=target):
                body = self.handle(self.event(target=target))

                self.assertEqual(body['decision'], 'REMEDIATE')
                self.assertEqual(body['remediation_result']['status'], 'blocked')
                self.iam.detach_user_policy.assert_not_called()

    def test_invalid_stale_or_future_live_events_never_detach(self):
        self.m.DRY_RUN = False
        now = 1800000000
        cases = [None, '', 'bad-date', 123, '2026-09-30T12:00:00']
        cases += [
            time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + offset))
            for offset in (-900, -901, 61)
        ]

        with patch.object(self.m.time, 'time', return_value=now):
            for raw_time in cases:
                with self.subTest(event_time=raw_time):
                    event = self.event()
                    event['detail']['eventTime'] = raw_time
                    body = self.handle(event)

                    self.assertEqual(body['decision'], 'REMEDIATE')
                    self.assertEqual(body['remediation_result']['status'], 'blocked')
                    self.iam.detach_user_policy.assert_not_called()

    def test_fresh_live_events_allow_only_expected_detach(self):
        self.m.DRY_RUN = False
        now = 1800000000

        with patch.object(self.m.time, 'time', return_value=now):
            for offset in (-899, 0, 60):
                with self.subTest(offset=offset):
                    self.iam.detach_user_policy.reset_mock()
                    event = self.event()
                    event['detail']['eventTime'] = time.strftime(
                        '%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + offset))
                    body = self.handle(event)

                    self.assertEqual(body['remediation_result']['status'], 'success')
                    self.iam.detach_user_policy.assert_called_once_with(
                        UserName='iam-test-user', PolicyArn=POLICY)

    def test_action_claim_uses_conditional_write_and_separate_table(self):
        event = self.event()
        with patch.object(self.m.time, 'time', return_value=1800000000):
            claim = self.m.claim_live_action(event['detail'], self.decision(event))

        self.assertEqual(claim['status'], 'claimed')
        args = self.ledger.put_item.call_args.kwargs
        self.assertEqual(args['ConditionExpression'], 'attribute_not_exists(action_key)')
        self.assertEqual(args['Item']['status'], 'IN_PROGRESS')
        self.assertEqual(args['Item']['owner_token'], claim['owner_token'])
        self.assertEqual(args['Item']['ttl_delete_at_epoch'], 1800086400)
        self.table.put_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_existing_action_claims_are_never_reclaimed(self):
        event = self.event()
        decision = self.decision(event)
        self.m.claim_live_action(event['detail'], decision)
        record = self.ledger.put_item.call_args.kwargs['Item']
        self.ledger.put_item.side_effect = FakeClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException'}})

        for state, expected in [('IN_PROGRESS', 'blocked'), ('COMPLETED', 'duplicate'),
                                ('UNKNOWN', 'blocked')]:
            with self.subTest(state=state):
                self.ledger.get_item.return_value = {'Item': dict(record, status=state)}
                result = self.m.claim_live_action(event['detail'], decision)
                self.assertEqual(result['status'], expected)
                self.ledger.get_item.assert_called_with(
                    Key={'action_key': record['action_key']}, ConsistentRead=True)

        changed = dict(record, status='COMPLETED', scope={})
        self.ledger.get_item.return_value = {'Item': changed}
        self.assertEqual(self.m.claim_live_action(event['detail'], decision)['status'], 'blocked')
        self.ledger.update_item.assert_not_called()
        self.ledger.delete_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_action_claim_requires_configuration_and_event_identity(self):
        event = self.event()
        decision = self.decision(event)

        with patch.object(self.m, 'ACTION_LEDGER_TABLE_NAME', ''):
            with self.assertRaisesRegex(RuntimeError, 'Action ledger not configured'):
                self.m.claim_live_action(event['detail'], decision)

        for field in ('eventID', 'recipientAccountId'):
            with self.subTest(field=field):
                detail = dict(event['detail'])
                detail.pop(field)
                self.assertEqual(self.m.claim_live_action(detail, decision)['status'], 'blocked')

        self.ledger.put_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_action_ledger_errors_never_become_successful_claims(self):
        event = self.event()
        decision = self.decision(event)
        failures = [FakeClientError({'Error': {'Code': 'AccessDeniedException'}}),
                    FakeBotoCoreError('timeout')]

        for failure in failures:
            with self.subTest(stage='put', failure=type(failure).__name__):
                self.ledger.put_item.side_effect = failure
                with self.assertRaisesRegex(RuntimeError, 'Action ledger'):
                    self.m.claim_live_action(event['detail'], decision)

        self.ledger.put_item.side_effect = FakeClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException'}})

        for failure in failures:
            with self.subTest(stage='get', failure=type(failure).__name__):
                self.ledger.get_item.side_effect = failure
                with self.assertRaisesRegex(RuntimeError, 'Action ledger'):
                    self.m.claim_live_action(event['detail'], decision)

        self.iam.detach_user_policy.assert_not_called()

    def test_action_completion_requires_owned_in_progress_record(self):
        event = self.event()
        claim = self.m.claim_live_action(event['detail'], self.decision(event))
        result = {
            'status': 'success',
            'action': 'detach_user_policy',
            'user_name': 'iam-test-user',
            'policy_arn': POLICY,
        }

        self.m.complete_live_action(claim, result)

        self.ledger.update_item.assert_called_once()
        args = self.ledger.update_item.call_args.kwargs
        self.assertEqual(args['Key'], {'action_key': claim['action_key']})
        self.assertEqual(
            args['ConditionExpression'],
            'attribute_exists(action_key) AND #status = :in_progress '
            'AND owner_token = :owner',
        )
        values = args['ExpressionAttributeValues']
        self.assertEqual(values[':owner'], claim['owner_token'])
        self.assertEqual(values[':in_progress'], 'IN_PROGRESS')
        self.assertEqual(values[':completed'], 'COMPLETED')
        self.assertEqual(values[':result'], result)
        self.table.update_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_action_completion_rejects_invalid_inputs(self):
        event = self.event()
        claim = self.m.claim_live_action(event['detail'], self.decision(event))

        with self.assertRaises(RuntimeError):
            self.m.complete_live_action({}, {'status': 'success'})

        with self.assertRaises(RuntimeError):
            self.m.complete_live_action(claim, {'status': 'error'})

        with patch.object(self.m, 'ACTION_LEDGER_TABLE_NAME', ''):
            with self.assertRaises(RuntimeError):
                self.m.complete_live_action(claim, {'status': 'success'})

        self.ledger.update_item.assert_not_called()

    def test_action_completion_failure_never_reclaims_or_deletes(self):
        event = self.event()
        claim = self.m.claim_live_action(event['detail'], self.decision(event))
        failures = [
            FakeClientError({'Error': {'Code': 'ConditionalCheckFailedException'}}),
            FakeBotoCoreError('timeout'),
        ]

        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.ledger.update_item.side_effect = failure
                with self.assertRaisesRegex(RuntimeError, 'completion uncertain'):
                    self.m.complete_live_action(claim, {'status': 'success'})

        self.assertEqual(self.ledger.put_item.call_count, 1)
        self.ledger.delete_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_live_handler_claims_then_detaches_then_completes(self):
        self.m.DRY_RUN = False
        sequence = MagicMock()
        sequence.attach_mock(self.ledger.put_item, 'claim')
        sequence.attach_mock(self.iam.detach_user_policy, 'detach')
        sequence.attach_mock(self.ledger.update_item, 'complete')

        self.assertEqual(self.handle()['remediation_result']['status'], 'success')
        self.assertEqual([call[0] for call in sequence.mock_calls],
                         ['claim', 'detach', 'complete'])
        self.table.put_item.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_completed_event_replay_does_not_detach_again(self):
        self.m.DRY_RUN = False
        event = self.event()
        self.assertEqual(self.handle(event)['remediation_result']['status'], 'success')

        record = dict(self.ledger.put_item.call_args.kwargs['Item'], status='COMPLETED')
        self.ledger.put_item.side_effect = FakeClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException'}})
        self.ledger.get_item.return_value = {'Item': record}

        replay = dict(event, id='different-eventbridge-delivery')
        self.assertEqual(self.handle(replay)['remediation_result']['status'], 'duplicate')
        self.iam.detach_user_policy.assert_called_once_with(
            UserName='iam-test-user', PolicyArn=POLICY)
        self.assertEqual(self.ledger.update_item.call_count, 1)

    def test_uncertain_iam_outcome_does_not_get_automatically_retried(self):
        self.m.DRY_RUN = False
        event = self.event()
        self.iam.detach_user_policy.side_effect = FakeBotoCoreError('timeout')

        with self.assertRaises(FakeBotoCoreError):
            self.handle(event)

        record = self.ledger.put_item.call_args.kwargs['Item']
        self.ledger.put_item.side_effect = FakeClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException'}})
        self.ledger.get_item.return_value = {'Item': record}
        self.iam.detach_user_policy.side_effect = None

        self.assertEqual(self.handle(event)['remediation_result']['status'], 'blocked')
        self.assertEqual(self.iam.detach_user_policy.call_count, 1)
        self.ledger.update_item.assert_not_called()

    def test_uncertain_completion_does_not_repeat_iam_action(self):
        self.m.DRY_RUN = False
        event = self.event()
        self.ledger.update_item.side_effect = FakeBotoCoreError('response lost')

        with self.assertRaisesRegex(RuntimeError, 'completion uncertain'):
            self.handle(event)

        record = self.ledger.put_item.call_args.kwargs['Item']
        self.ledger.put_item.side_effect = FakeClientError(
            {'Error': {'Code': 'ConditionalCheckFailedException'}})
        self.ledger.update_item.side_effect = None

        for state, expected in [('IN_PROGRESS', 'blocked'), ('COMPLETED', 'duplicate')]:
            with self.subTest(state=state):
                self.ledger.get_item.return_value = {'Item': dict(record, status=state)}
                self.assertEqual(self.handle(event)['remediation_result']['status'], expected)

        self.assertEqual(self.iam.detach_user_policy.call_count, 1)
        self.assertEqual(self.ledger.update_item.call_count, 1)

    def test_handler_ledger_failure_prevents_iam_action(self):
        self.m.DRY_RUN = False
        self.ledger.put_item.side_effect = FakeClientError(
            {'Error': {'Code': 'AccessDeniedException'}})

        with self.assertRaisesRegex(RuntimeError, 'Action ledger claim failed'):
            self.handle()

        self.iam.detach_user_policy.assert_not_called()
        self.ledger.update_item.assert_not_called()

    def test_safe_paths_do_not_write_action_ledger(self):
        self.assertEqual(self.handle()['remediation_result']['status'], 'dry_run')
        self.m.DRY_RUN = False
        self.assertEqual(self.handle(self.event(target='production-user'))['decision'], 'NO_ACTION')
        self.assertEqual(self.handle(self.event(target='iam-test-other'))[
            'remediation_result']['status'], 'blocked')

        stale = self.event()
        stale['detail']['eventTime'] = '2000-01-01T00:00:00Z'
        self.assertEqual(self.handle(stale)['remediation_result']['status'], 'blocked')

        self.record()
        self.assertEqual(self.handle()['decision'], 'SKIP_APPROVED')
        self.ledger.put_item.assert_not_called()
        self.ledger.update_item.assert_not_called()
        self.iam.detach_user_policy.assert_not_called()

    def test_live_iam_failure_raises(self):
        self.m.DRY_RUN = False
        self.iam.detach_user_policy.side_effect = FakeClientError({'Error': {'Code': 'AccessDenied'}})
        with self.assertRaisesRegex(RuntimeError, 'IAM remediation failed'):
            self.handle()

    def test_live_detach_targets_only_expected_user_policy(self):
        self.m.DRY_RUN = False
        self.assertEqual(self.handle()['remediation_result']['status'], 'success')
        self.iam.detach_user_policy.assert_called_once_with(UserName='iam-test-user', PolicyArn=POLICY)

    def test_repeated_detach_of_absent_target_is_no_op(self):
        parsed = self.m.parse_attach_user_policy(self.event()['detail'])
        self.iam.detach_user_policy.side_effect = [
            None, FakeClientError({'Error': {'Code': 'NoSuchEntity'}}),
        ]
        self.assertEqual(self.m.remediate_attach_user_policy(parsed)['status'], 'success')
        result = self.m.remediate_attach_user_policy(parsed)
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['outcome'], 'target_already_absent')

    def test_unexpected_error_is_not_swallowed(self):
        with patch.object(self.m, 'evaluate', side_effect=ValueError('unexpected')):
            with self.assertRaisesRegex(ValueError, 'unexpected'):
                self.handle()

    def test_only_explicit_false_disables_dry_run(self):
        for setting, expected in [('true', True), ('tru', True), ('', True), ('0', True), (' false ', False)]:
            with self.subTest(setting=setting), patch.dict(os.environ, {'DRY_RUN': setting}):
                self.assertIs(self.load().DRY_RUN, expected)
        with patch.dict(os.environ):
            os.environ.pop('DRY_RUN', None)
            self.assertIs(self.load().DRY_RUN, True)

    def test_outside_scope_live_mode_still_never_mutates(self):
        self.m.DRY_RUN = False
        body = self.handle(self.event(target='production-user'))
        self.assertEqual(body['decision'], 'NO_ACTION')
        self.iam.detach_user_policy.assert_not_called()

    def test_dlq_validation_fixture_raises_before_mutation(self):
        fixture = SOURCE.parents[2] / 'tests' / 'fixtures' / 'dlq-invalid-event.json'
        event = json.loads(fixture.read_text())
        with self.assertRaises(AttributeError):
            self.handle(event)
        self.iam.detach_user_policy.assert_not_called()

if __name__ == '__main__':
    unittest.main()
