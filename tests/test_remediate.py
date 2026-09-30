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
        self.table = MagicMock()
        self.table.get_item.return_value = {}
        self.db = MagicMock()
        self.db.Table.return_value = self.table
        boto = types.ModuleType('boto3')
        boto.client = lambda service, **kwargs: {'iam': self.iam, 'sns': self.sns}[service]
        boto.resource = lambda service, **kwargs: self.db
        core = types.ModuleType('botocore')
        errors = types.ModuleType('botocore.exceptions')
        errors.ClientError = FakeClientError
        errors.BotoCoreError = FakeBotoCoreError
        self.env = patch.dict(os.environ, {
            'DRY_RUN': 'true', 'EXCEPTION_TABLE_NAME': 'test-exceptions',
            'EXCEPTION_TABLE_REGION': 'us-east-1',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-alerts',
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
        return {'id': 'event-test-1', 'detail': {
            'eventName': 'AttachUserPolicy', 'eventSource': 'iam.amazonaws.com',
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
        self.m.DRY_RUN = False
        self.iam.detach_user_policy.side_effect = [None, FakeClientError({'Error': {'Code': 'NoSuchEntity'}})]
        self.assertEqual(self.handle()['remediation_result']['status'], 'success')
        result = self.handle()['remediation_result']
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
