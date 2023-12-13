#!/usr/bin/env python3

# Copyright 2021 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Define keystone tests."""

import base64

import ops_sunbeam.test_utils as test_utils
from ops.testing import Harness

import charm


class _KeystoneOpenIDCK8SCharm(charm.KeystoneOpenIDCK8SCharm):
    """Create Keystone operator test charm."""

    def __init__(self, framework):
        self.seen_events = []
        super().__init__(framework)

    def _log_event(self, event):
        self.seen_events.append(type(event).__name__)

    def configure_charm(self, event):
        super().configure_charm(event)
        self._log_event(event)

    @property
    def public_ingress_address(self) -> str:
        return "10.0.0.10"


class TestKeystoneOpenIDCK8SCharm(test_utils.CharmTestCase):
    def setUp(self):
        """Run test setup."""
        self.harness = Harness(charm.KeystoneOpenIDCK8SCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_charm(self):
        """Test pebble ready handler."""
        self.harness.set_leader()
        peer_rel_id = self.harness.add_relation("peers", "keystone-openidc-k8s")
        rel_id = self.harness.add_relation("openidc-config", "keystone")
        self.harness.add_relation_unit(rel_id, "keystone/0")
        rel_data = self.harness.get_relation_data(rel_id, self.harness.charm.unit.app.name)
        self.harness.update_config(
            {
                "oidc-provider-metadata-url": "http://openidc.example.org",
                "oidc-client-id": "client1",
                "oidc-client-secret": "asecret",
            }
        )
        self.harness.update_relation_data(
            rel_id, "keystone", {"keystone_ip": "10.0.0.10", "keystone_port": "5000"}
        )
        secret = self.harness.add_model_secret(
            "keystone-openidc-k8s", {"crypto-passphrase": "a-passphrase"}
        )
        self.harness.update_relation_data(
            peer_rel_id, "keystone-openidc-k8s", {"oidc-crypto-passphrase": secret}
        )
        openidc_apache_config_file = base64.b64decode(rel_data["config-contents"]).decode()
        self.assertIn(
            "OIDCProviderMetadataURL http://openidc.example.org", openidc_apache_config_file
        )
        self.assertIn("OIDCClientID client1", openidc_apache_config_file)
        self.assertIn("OIDCClientSecret asecret", openidc_apache_config_file)
