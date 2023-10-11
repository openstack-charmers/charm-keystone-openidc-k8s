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
import json
import logging
from typing import Callable, List, Mapping, Optional

import requests
import jinja2
import ops.charm
import ops_sunbeam.charm as sunbeam_charm
import ops_sunbeam.config_contexts as config_contexts
import ops_sunbeam.relation_handlers as sunbeam_rhandlers
from ops.main import main

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)


class OpenIDCConfigContext(config_contexts.ConfigContext):
    """Configuration context for cinder parameters."""

    def _get_principal_data(self):
        relation = self.charm_instance.model.get_relation(
            'keystone-fid-service-provider')
        if relation and len(relation.units) > 0:
            logger.debug('related units via keystone-fid-service-provider: %s',
                         relation.units)
            return relation.data[list(relation.units)[0]]
        else:
            logger.debug('There are no related units via '
                         'keystone-fid-service-provider')
            return None

    @property
    def hostname(self) -> Optional[str]:
        """Hostname as advertised by the principal charm."""
        data = self._get_principal_data()
        try:
            return json.loads(data['hostname'])
        except (TypeError, KeyError):
            logger.debug('keystone hostname no available yet')
            return None

    @property
    def openidc_location_config(self) -> str:
        """Path to the file with the OpenID Connect configuration."""
        return os.path.join(self.charm_instance.config_dir,
                            f'openidc-location.{self.idp_id}.conf')

    @property
    def oidc_auth_path(self) -> str:
        return (f'/v3/OS-FEDERATION/identity_providers/{self.idp_id}'
                f'/protocols/openid/auth')

    @property
    def idp_id(self) -> str:
        """Identity provider name to use for URL generation."""
        return 'openid'

    @property
    def scheme(self) -> Optional[str]:
        data = self._get_principal_data()
        try:
            tls_enabled = json.loads(data['tls-enabled'])
            return 'https' if tls_enabled else 'http'
        except (TypeError, KeyError):
            return None

    @property
    def port(self) -> Optional[int]:
        data = self._get_principal_data()
        try:
            return json.loads(data['port'])
        except (TypeError, KeyError):
            return None

    @property
    def oidc_crypto_passphrase(self) -> Optional[str]:

        relation = self.charm_instance.model.get_relation('cluster')
        if not relation:
            return None
        data = relation.data[self.charm_instance.unit.app]

        if not data:
            logger.debug('data bag on peer relation not found, the cluster '
                         'relation is not ready.')
            return None

        crypto_passphrase = data.get('oidc-crypto-passphrase')
        if crypto_passphrase:
            logger.debug('Using oidc-crypto-passphrase from app databag')
            return crypto_passphrase
        else:
            logger.warning('The oidc-crypto-passphrase has not been set')
            return None

    @property
    def provider_metadata(self):
        """Metadata content offered by the Identity Provider.

        The content available at the url configured in
        oidc-provider-metadata-url is read and parsed as json.
        """
        if self.charm.config['oidc-provider-metadata-url']:
            logging.info('GETing content from %s',
                         self.charm.config['oidc-provider-metadata-url'])
            try:
                 # XXX Support TLS !!
#                r = requests.get(self.charm.config['oidc-provider-metadata-url'],
#                                 verify=SYSTEM_CA_CERT)
                r = requests.get(self.charm.config['oidc-provider-metadata-url'])
                return r.json()
            except Exception:
                logger.exception(('Failed to GET json content from provider '
                                  'metadata url: %s'),
                                 self.charm.config['oidc-provider-metadata-url'])
                return None
        else:
            logging.info('Metadata was not retrieved since '
                         'oidc-provider-metadata-url is not set')
            return None

    @property
    def oauth_introspection_endpoint(self):
        if self.charm.config['oidc-oauth-introspection-endpoint']:
            logger.debug('Using oidc_oauth_introspection_endpoint from config')
            return self.charm.config['oidc-oauth-introspection-endpoint']

        metadata = self.provider_metadata
        if 'introspection_endpoint' in metadata:
            logger.debug('Using introspection_endpoint from metadata')
            return metadata['introspection_endpoint']
        else:
            logger.warning('OAuth introspection endpoint not found '
                           'in metadata')
            return None

    def context(self) -> dict:
        """Generate context information for cinder config."""
        config = {
            'auth_type': self.charm.config['auth-type'],
            'hostname': "10.152.183.177", # XXX This should be the cluster vip from keystone
            'idp_id': self.idp_id,
            'oauth_introspection_endpoint': self.oauth_introspection_endpoint,
            'oidc_auth_path': self.oidc_auth_path,
            'oidc_client_id': self.charm.config['oidc-client-id'],
            'oidc_client_secret': self.charm.config['oidc-client-secret'],
            'oidc_crypto_passphrase': self.charm.oidc_crypto_passphrase,
            'oidc_oauth_verify_jwks_uri': self.charm.config['oidc-oauth-verify-jwks-uri'],
            'oidc_provider_auth_endpoint': self.charm.config['oidc-provider-auth-endpoint'],
            'oidc_provider_issuer': self.charm.config['oidc-provider-issuer'],
            'oidc_provider_jwks_uri': self.charm.config['oidc-provider-jwks-uri'],
            'OIDC_provider_metadata_url': self.charm.config['oidc-provider-metadata-url'],
            'oidc_provider_token_endpoint': self.charm.config['oidc-provider-token-endpoint'],
            'oidc_provider_token_endpoint_auth': self.charm.config['oidc-provider-token-endpoint-auth'],
            'oidc_provider_user_info_endpoint': self.charm.config['oidc-provider-user-info-endpoint'],
            'oidc_remote_user_claim': self.charm.config['oidc-remote-user-claim'],
            'port': "5000",
            'protocol_id': self.charm.config['protocol_id'],
            'remote_id_attribute': self.charm.config['remote-id-attribute'],
            'scheme': 'http',
            'enable_oauth': 'True',
        }
        print(config)
        return {"config": config}


class DomainConfigProvidesHandler(sunbeam_rhandlers.RelationHandler):
    """Handler for identity credentials relation."""

    def __init__(
        self,
        charm: ops.charm.CharmBase,
        relation_name: str,
        callback_f: Callable,
    ):
        super().__init__(charm, relation_name, callback_f)


    def setup_event_handler(self):
        """Configure event handlers for a domain config relation."""
        logger.debug("Setting up domain config event handler")
        self.domain_config = sunbeam_dc_svc.DomainConfigProvides(
            self.charm,
            self.relation_name,
        )
        self.framework.observe(
            self.domain_config.on.remote_ready,
            self._on_domain_config_ready,
        )
        return self.domain_config

    def _on_domain_config_ready(self, event) -> None:
        """Handles domain config change events."""
        self.callback_f(event)

    @property
    def ready(self) -> bool:
        """Check if handler is ready."""
        return True


class KeystoneOpenIDCK8SCharm(sunbeam_charm.OSBaseOperatorCharm):
    """Charm the service."""

    DOMAIN_CONFIG_RELATION_NAME = "domain-config"

    def __init__(self, *args):
        super().__init__(*args)

    def get_relation_handlers(self, handlers=None) -> List[sunbeam_rhandlers.RelationHandler]:
        """Relation handlers for the service."""
        return []
        handlers = handlers or []
        if self.can_add_handler(self.DOMAIN_CONFIG_RELATION_NAME, handlers):
            self.dc_handler = DomainConfigProvidesHandler(
                self,
                self.DOMAIN_CONFIG_RELATION_NAME,
                self.send_domain_config,
            )
            handlers.append(self.dc_handler)
        return super().get_relation_handlers(handlers)

    @property
    def oidc_crypto_passphrase(self):
        # Generate and store on peer relation
        return "16563eeb-f94b-401a-a61d-d11df4b2f704"

    @property
    def config_contexts(self) -> List[config_contexts.ConfigContext]:
        """Configuration contexts for the operator."""
        contexts = super().config_contexts
        contexts.append(OpenIDCConfigContext(self, "openidc_config"))
        return contexts

    def send_openidc_config(self, event=None) -> None:
        """Send domain configuration to keystone."""
        print("send_openidc_config")
        try:
            # XXX Check a few more
            self.config["oidc-client-secret"]
        except KeyError:
            return
        loader = jinja2.FileSystemLoader(self.template_dir)
        _tmpl_env = jinja2.Environment(loader=loader)
        template = _tmpl_env.get_template("apache-openidc-location.conf")
        print(template.render(self.contexts()))
        #self.dc_handler.domain_config.set_domain_info(
        #    domain_name=domain_name, config_contents=template.render(self.contexts())
        #)

    def configure_app_leader(self, event) -> None:
        """Configure application."""
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
