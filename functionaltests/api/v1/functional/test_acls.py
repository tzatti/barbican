# Copyright (c) 2015 Cisco Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from testtools import testcase

from barbican.tests import utils
from functionaltests.api import base
from functionaltests.api.v1.behaviors import acl_behaviors
from functionaltests.api.v1.behaviors import container_behaviors
from functionaltests.api.v1.behaviors import secret_behaviors
from functionaltests.api.v1.models import acl_models
from functionaltests.api.v1.models import container_models
from functionaltests.api.v1.models import secret_models
from functionaltests.common import config


CONF = config.get_config()
admin_a = CONF.rbac_users.admin_a
creator_a = CONF.rbac_users.creator_a
observer_a = CONF.rbac_users.observer_a
auditor_a = CONF.rbac_users.auditor_a
admin_b = CONF.rbac_users.admin_b
observer_b = CONF.rbac_users.observer_b


def get_rbac_only():
    return {'read': {'project-access': True}}


# private secret can only be access by the creator or an admin
def get_private():
    return {'read': {'project-access': False}}


def get_acl_only(reader_id):
    return {'read': {'users': [reader_id], 'project-access': False}}


def get_rbac_plus_acl(reader_id):
    return {'read': {'users': [reader_id], 'project-access': True}}


test_data_read_secret_rbac_only = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_read_secret_private = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_read_secret_acl_only = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 200},
}

test_data_read_secret_rbac_plus_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 200},
}

test_data_read_container_rbac_only = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 200},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_read_container_private = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 403},
}

test_data_read_container_acl_only = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 403},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 403},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 200},
}

test_data_read_container_rbac_plus_acl = {
    'with_admin_a': {'user': admin_a, 'expected_return': 200},
    'with_creator_a': {'user': creator_a, 'expected_return': 200},
    'with_observer_a': {'user': observer_a, 'expected_return': 200},
    'with_auditor_a': {'user': auditor_a, 'expected_return': 200},
    'with_admin_b': {'user': admin_b, 'expected_return': 403},
    'with_observer_b': {'user': observer_b, 'expected_return': 200},
}


@utils.parameterized_test_case
class AclTestCase(base.TestCase):
    """Functional tests exercising ACL Features"""
    def setUp(self):
        super(AclTestCase, self).setUp()
        self.secret_behaviors = secret_behaviors.SecretBehaviors(self.client)
        self.container_behaviors = container_behaviors.ContainerBehaviors(
            self.client)
        self.acl_behaviors = acl_behaviors.AclBehaviors(self.client)

    def tearDown(self):
        self.acl_behaviors.delete_all_created_acls()
        self.secret_behaviors.delete_all_created_secrets()
        self.container_behaviors.delete_all_created_containers()
        super(AclTestCase, self).tearDown()

    @utils.parameterized_dataset(test_data_read_secret_rbac_only)
    def test_secret_read_default(self, user, expected_return):
        secret_ref = self.store_secret()
        status = self.get_secret(secret_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_secret_rbac_only)
    def test_secret_read_rbac_only(self, user, expected_return):
        secret_ref = self.store_secret()
        self.set_secret_acl(secret_ref, get_rbac_only())
        status = self.get_secret(secret_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_secret_private)
    def test_secret_read_private(self, user, expected_return):
        secret_ref = self.store_secret()
        self.set_secret_acl(secret_ref, get_private())
        status = self.get_secret(secret_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_secret_acl_only)
    def test_secret_read_acl_only(self, user, expected_return):
        secret_ref = self.store_secret()
        user_id = self.secret_behaviors.get_user_id_from_name(observer_b)
        self.set_secret_acl(secret_ref, get_acl_only(user_id))
        status = self.get_secret(secret_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_secret_rbac_plus_acl)
    def test_secret_read_rbac_plus_acl(self, user, expected_return):
        secret_ref = self.store_secret()
        user_id = self.secret_behaviors.get_user_id_from_name(observer_b)
        self.set_secret_acl(secret_ref, get_rbac_plus_acl(user_id))
        status = self.get_secret(secret_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_container_rbac_only)
    def test_container_read_default(self, user, expected_return):
        container_ref = self.store_container()
        status = self.get_container(container_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_container_rbac_only)
    def test_container_read_rbac_only(self, user, expected_return):
        container_ref = self.store_container()
        self.set_container_acl(container_ref, get_rbac_only())
        status = self.get_container(container_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_container_private)
    def test_container_read_private(self, user, expected_return):
        container_ref = self.store_container()
        self.set_container_acl(container_ref, get_private())
        status = self.get_container(container_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_container_acl_only)
    def test_container_read_acl_only(self, user, expected_return):
        container_ref = self.store_container()
        user_id = self.container_behaviors.get_user_id_from_name(observer_b)
        self.set_container_acl(container_ref, get_acl_only(user_id))
        status = self.get_container(container_ref, user_name=user)
        self.assertEqual(expected_return, status)

    @utils.parameterized_dataset(test_data_read_container_rbac_plus_acl)
    def test_container_read_rbac_plus_acl(self, user, expected_return):
        container_ref = self.store_container()
        user_id = self.container_behaviors.get_user_id_from_name(observer_b)
        self.set_container_acl(container_ref, get_rbac_plus_acl(user_id))
        status = self.get_container(container_ref, user_name=user)
        self.assertEqual(expected_return, status)

# ----------------------- Secret ACL Tests ---------------------------

    @testcase.attr('negative', 'security')
    def test_secret_read_acl_no_token(self):
        secret_ref = self.store_secret()
        acl_ref = '{0}/acl'.format(secret_ref)
        resp = self.acl_behaviors.get_acl(acl_ref, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_set_acl_no_token(self):
        secret_ref = self.store_secret()
        resp = self.set_secret_acl(secret_ref, get_rbac_only(), use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_delete_acl_no_token(self):
        secret_ref = self.store_secret()
        acl_ref = '{0}/acl'.format(secret_ref)
        resp = self.acl_behaviors.delete_acl(
            acl_ref, expected_fail=True, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_secret_update_acl_no_token(self):
        secret_ref = self.store_secret()
        acl_ref = '{0}/acl'.format(secret_ref)
        resp = self.set_secret_acl(secret_ref, get_rbac_only())
        self.assertEqual(200, resp.status_code)
        resp = self.acl_behaviors.update_acl(acl_ref, {}, use_auth=False)
        self.assertEqual(401, resp.status_code)

# ----------------------- Container ACL Tests ---------------------------

    @testcase.attr('negative', 'security')
    def test_container_read_acl_no_token(self):
        container_ref = self.store_container()
        acl_ref = '{0}/acl'.format(container_ref)
        resp = self.acl_behaviors.get_acl(acl_ref, use_auth=False)
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_container_set_acl_no_token(self):
        container_ref = self.store_container()
        resp = self.set_container_acl(
            container_ref, get_rbac_only(), use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_container_delete_acl_no_token(self):
        container_ref = self.store_container()
        acl_ref = '{0}/acl'.format(container_ref)
        resp = self.acl_behaviors.delete_acl(
            acl_ref, expected_fail=True, use_auth=False
        )
        self.assertEqual(401, resp.status_code)

    @testcase.attr('negative', 'security')
    def test_container_update_acl_no_token(self):
        container_ref = self.store_container()
        acl_ref = '{0}/acl'.format(container_ref)
        resp = self.set_container_acl(container_ref, get_rbac_only())
        self.assertEqual(200, resp.status_code)
        resp = self.acl_behaviors.update_acl(acl_ref, {}, use_auth=False)
        self.assertEqual(401, resp.status_code)

# ----------------------- Helper Functions ---------------------------

    def store_secret(self, user_name=creator_a, admin=admin_a):
        test_model = secret_models.SecretModel(
            **get_default_secret_data())
        resp, secret_ref = self.secret_behaviors.create_secret(
            test_model, user_name=user_name, admin=admin)
        self.assertEqual(201, resp.status_code)
        return secret_ref

    def get_secret(self, secret_ref, user_name=creator_a):
        resp = self.secret_behaviors.get_secret(
            secret_ref, 'application/octet-stream',
            user_name=user_name)
        return resp.status_code

    def set_secret_acl(self, secret_ref, acl, use_auth=True,
                       user_name=creator_a):
        test_model = acl_models.AclModel(**acl)
        resp = self.acl_behaviors.create_acl(
            secret_ref, test_model, use_auth=use_auth, user_name=user_name)
        if use_auth:
            self.assertEqual(200, resp.status_code)
        return resp

    def store_container(self, user_name=creator_a, admin=admin_a):
        secret_ref = self.store_secret(user_name=user_name, admin=admin)

        test_model = container_models.ContainerModel(
            **get_container_req(secret_ref))
        resp, container_ref = self.container_behaviors.create_container(
            test_model, user_name=user_name, admin=admin)
        self.assertEqual(201, resp.status_code)
        return container_ref

    def get_container(self, container_ref, user_name=creator_a):
        resp = self.container_behaviors.get_container(
            container_ref, user_name=user_name)
        return resp.status_code

    def set_container_acl(self, container_ref, acl, use_auth=True,
                          user_name=creator_a):
        test_model = acl_models.AclModel(**acl)
        resp = self.acl_behaviors.create_acl(
            container_ref, test_model, use_auth=use_auth, user_name=user_name)
        if use_auth:
            self.assertEqual(200, resp.status_code)
        return resp

# ----------------------- Support Functions ---------------------------


def get_default_secret_data():
    return {
        "name": "AES key",
        "expiration": "2050-02-28T19:14:44.180394",
        "algorithm": "aes",
        "bit_length": 256,
        "mode": "cbc",
        "payload": get_default_payload(),
        "payload_content_type": "application/octet-stream",
        "payload_content_encoding": "base64",
    }


def get_default_payload():
    return 'Z0Y2K2xMb0Yzb2hBOWFQUnB0KzZiUT09'


def get_container_req(secret_ref):
    return {"name": "testcontainer",
            "type": "generic",
            "secret_refs": [{'name': 'secret1', 'secret_ref': secret_ref}]}
