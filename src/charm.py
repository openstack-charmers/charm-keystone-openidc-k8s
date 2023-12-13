#!/usr/bin/env python3
#
# Copyright 2023 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Learn more at: https://juju.is/docs/sdk

"""Keystone OpenIDC configuration.

Send domain configuration to the keystone charm.
"""
import logging
import os
import subprocess
import uuid
from pathlib import Path
from typing import Callable, List, Mapping, Optional

import charms.keystone_k8s.v0.openidc_config as sunbeam_openidc_svc
import jinja2
import ops.charm
import ops_sunbeam.charm as sunbeam_charm
import ops_sunbeam.config_contexts as config_contexts
import ops_sunbeam.relation_handlers as sunbeam_rhandlers
import requests
from ops.main import main
from ops.model import SecretRotate

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)


class OpenIDCConfigContext(config_contexts.ConfigContext):
    """Configuration context for cinder parameters."""

    def _get_principal_data(self):
        return self.charm.openidc_handler.get_keystone_info()

    @property
    def hostname(self) -> Optional[str]:
        """Hostname as advertised by the principal charm."""
        data = self._get_principal_data()
        return data.get("ip")

    @property
    def port(self) -> Optional[str]:
        """Hostname as advertised by the principal charm."""
        data = self._get_principal_data()
        return data.get("port")

    @property
    def openidc_location_config(self) -> str:
        """Path to the file with the OpenID Connect configuration."""
        return os.path.join(self.charm_instance.config_dir, f"openidc-location.{self.idp_id}.conf")

    @property
    def oidc_auth_path(self) -> str:
        """Path part of url for auth ep."""
        return f"/v3/OS-FEDERATION/identity_providers/{self.idp_id}" f"/protocols/openid/auth"

    @property
    def idp_id(self) -> str:
        """Identity provider name to use for URL generation."""
        return "openid"

    @property
    def provider_metadata(self):
        """Metadata content offered by the Identity Provider.

        The content available at the url configured in
        oidc-provider-metadata-url is read and parsed as json.
        """
        if self.charm.config["oidc-provider-metadata-url"]:
            logging.info(
                "Getting content from %s", self.charm.config["oidc-provider-metadata-url"]
            )
            try:
                if self.charm.config.get("tls-ca"):
                    r = requests.get(
                        self.charm.config["oidc-provider-metadata-url"],
                        verify=self.charm.IDC_CA_FILE,
                    )
                else:
                    r = requests.get(self.charm.config["oidc-provider-metadata-url"])
                return r.json()
            except Exception:
                logger.exception(
                    ("Failed to GET json content from provider " "metadata url: %s"),
                    self.charm.config["oidc-provider-metadata-url"],
                )
                return None
        else:
            logging.info(
                "Metadata was not retrieved since " "oidc-provider-metadata-url is not set"
            )
            return None

    @property
    def oauth_introspection_endpoint(self):
        """Endpoint to retrieve oauth config."""
        if self.charm.config["oidc-oauth-introspection-endpoint"]:
            logger.debug("Using oidc_oauth_introspection_endpoint from config")
            return self.charm.config["oidc-oauth-introspection-endpoint"]

        metadata = self.provider_metadata
        if metadata and "introspection_endpoint" in metadata:
            logger.debug("Using introspection_endpoint from metadata")
            return metadata["introspection_endpoint"]
        else:
            logger.warning("OAuth introspection endpoint not found " "in metadata")
            return None

    def context(self) -> dict:
        """Generate context information for cinder config."""
        config = {
            "auth_type": self.charm.config["auth-type"],
            "hostname": self.hostname,
            "idp_id": self.idp_id,
            "oauth_introspection_endpoint": self.oauth_introspection_endpoint,
            "oidc_auth_path": self.oidc_auth_path,
            "oidc_client_id": self.charm.config["oidc-client-id"],
            "oidc_client_secret": self.charm.config["oidc-client-secret"],
            "oidc_crypto_passphrase": self.charm.oidc_crypto_passphrase,
            "oidc_oauth_verify_jwks_uri": self.charm.config["oidc-oauth-verify-jwks-uri"],
            "oidc_provider_auth_endpoint": self.charm.config["oidc-provider-auth-endpoint"],
            "oidc_provider_issuer": self.charm.config["oidc-provider-issuer"],
            "oidc_provider_jwks_uri": self.charm.config["oidc-provider-jwks-uri"],
            "oidc_provider_metadata_url": self.charm.config["oidc-provider-metadata-url"],
            "oidc_provider_token_endpoint": self.charm.config["oidc-provider-token-endpoint"],
            "oidc_provider_token_endpoint_auth": self.charm.config[
                "oidc-provider-token-endpoint-auth"
            ],
            "oidc_provider_user_info_endpoint": self.charm.config[
                "oidc-provider-user-info-endpoint"
            ],
            "oidc_remote_user_claim": self.charm.config["oidc-remote-user-claim"],
            "port": self.port,
            "protocol_id": self.charm.config["protocol_id"],
            "remote_id_attribute": self.charm.config["remote-id-attribute"],
            "scheme": "http",
            "enable_oauth": "True",
        }
        return {"config": config}


class OpenIDCConfigProvidesHandler(sunbeam_rhandlers.RelationHandler):
    """Handler for identity credentials relation."""

    def __init__(
        self,
        charm: ops.charm.CharmBase,
        relation_name: str,
        callback_f: Callable,
    ):
        super().__init__(charm, relation_name, callback_f)

    def setup_event_handler(self):
        """Configure event handlers for a openidc config relation."""
        logger.debug("Setting up openidc config event handler")
        self.openidc_config = sunbeam_openidc_svc.OpenIDCConfigProvides(
            self.charm,
            self.relation_name,
        )
        self.framework.observe(
            self.openidc_config.on.remote_ready,
            self._on_openidc_config_ready,
        )
        return self.openidc_config

    def _on_openidc_config_ready(self, event) -> None:
        """Handles openidc config change events."""
        self.callback_f(event)

    def get_keystone_info(self) -> None:
        """Handles openidc config change events."""
        return self.openidc_config.get_keystone_info()

    @property
    def ready(self) -> bool:
        """Check if handler is ready."""
        return True


class KeystoneOpenIDCK8SCharm(sunbeam_charm.OSBaseOperatorCharm):
    """Charm the service."""

    OPENIDC_CONFIG_RELATION_NAME = "openidc-config"
    IDC_CA_FILE = Path("/usr/local/share/ca-certificates/idc_server.crt")
    OIDC_CRYPTO_PASSPHRASE_SECRET_KEY = "oidc-crypto-passphrase"

    def __init__(self, *args):
        super().__init__(*args)

    def config_valid(self):
        """Check if charm has everything it needs to render config."""
        mandatory_config = ["oidc-provider-metadata-url", "oidc-client-id", "oidc-client-secret"]
        for c in mandatory_config:
            if not self.config[c]:
                logger.debug(f"Charm config item {mandatory_config} not set")
                return False
        if not self.oidc_crypto_passphrase:
            logger.debug("oidc_crypto_passphrase not configured yet")
            return False
        if not self.openidc_handler.get_keystone_info():
            logger.debug("Client data missing")
            return False
        return True

    def get_relation_handlers(self, handlers=None) -> List[sunbeam_rhandlers.RelationHandler]:
        """Relation handlers for the service."""
        handlers = handlers or []
        if self.can_add_handler(self.OPENIDC_CONFIG_RELATION_NAME, handlers):
            self.openidc_handler = OpenIDCConfigProvidesHandler(
                self,
                self.OPENIDC_CONFIG_RELATION_NAME,
                self.configure_charm,
            )
            handlers.append(self.openidc_handler)
        return super().get_relation_handlers(handlers)

    def _set_or_update_oidc_crypto_passphrase(self) -> str:
        """Create oidc_crypto_passphrase secret or update it."""
        oidc_crypto_passphrase_uuid_id = self.peers.get_app_data(
            self.OIDC_CRYPTO_PASSPHRASE_SECRET_KEY
        )
        if oidc_crypto_passphrase_uuid_id:
            secret = self.model.get_secret(id=oidc_crypto_passphrase_uuid_id)
        else:
            secret = self.model.app.add_secret(
                {
                    "crypto-passphrase": str(uuid.uuid4()),
                },
                label=self.OIDC_CRYPTO_PASSPHRASE_SECRET_KEY,
                rotate=SecretRotate.NEVER,
            )
            self.peers.set_app_data(
                {
                    self.OIDC_CRYPTO_PASSPHRASE_SECRET_KEY: secret.id,
                }
            )

        return secret.id

    @property
    def oidc_crypto_passphrase(self):
        """Get the secret crypto_passphrase."""
        uuid = None
        oidc_crypto_passphrase_uuid_id = self.peers.get_app_data(
            self.OIDC_CRYPTO_PASSPHRASE_SECRET_KEY
        )
        if oidc_crypto_passphrase_uuid_id:
            secret = self.model.get_secret(id=oidc_crypto_passphrase_uuid_id)
            secret_data = secret.get_content()
            uuid = secret_data["crypto-passphrase"]
        return uuid

    @property
    def config_contexts(self) -> List[config_contexts.ConfigContext]:
        """Configuration contexts for the operator."""
        contexts = super().config_contexts
        contexts.append(OpenIDCConfigContext(self, "openidc_config"))
        return contexts

    def send_openidc_config(self, event=None) -> None:
        """Send domain configuration to keystone."""
        loader = jinja2.FileSystemLoader(self.template_dir)
        _tmpl_env = jinja2.Environment(loader=loader)
        template = _tmpl_env.get_template("apache-openidc-location.conf")
        self.openidc_handler.openidc_config.set_openidc_info(
            openidc_name="Remove this?",
            config_contents=template.render(self.contexts()),
            ca=self.config.get("tls-ca"),
        )

    def configure_unit(self, event: ops.framework.EventBase) -> None:
        """Run configuration on this unit."""
        super().configure_unit(event)
        if self.config.get("tls-ca"):
            with self.IDC_CA_FILE.open(mode="w") as ca_file:
                ca_file.write(self.config["tls-ca"])
            subprocess.check_call(["update-ca-certificates"])

    def configure_app_leader(self, event) -> None:
        """Configure application."""
        self._set_or_update_oidc_crypto_passphrase()
        if self.config_valid():
            self.send_openidc_config()
            self.set_leader_ready()

    @property
    def databases(self) -> Mapping[str, str]:
        """Config charm has no databases."""
        return {}

    def get_pebble_handlers(self):
        """Config charm has no containers."""
        return []


if __name__ == "__main__":  # pragma: nocover
    main(KeystoneOpenIDCK8SCharm)
