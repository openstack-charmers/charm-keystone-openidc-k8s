"""Interface for passing openidc configuration."""

import logging
from typing import (
    Optional,
)

from ops.charm import (
    CharmBase,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationEvent,
)
from ops.framework import (
    EventSource,
    Object,
    ObjectEvents,
)
from ops.model import (
    Relation,
)
import base64
logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "d368e807fd8e4543b5aa87099913dbdf"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

class OpenIDCConfigRequestEvent(RelationEvent):
    """OpenIDCConfigRequest Event."""
    pass

class OpenIDCConfigProviderEvents(ObjectEvents):
    """Events class for `on`."""

    remote_ready = EventSource(OpenIDCConfigRequestEvent)

class OpenIDCConfigProvides(Object):
    """OpenIDCConfigProvides class."""

    on = OpenIDCConfigProviderEvents()

    def __init__(self, charm: CharmBase, relation_name: str):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_openidc_config_relation_changed,
        )

    def _on_openidc_config_relation_changed(
        self, event: RelationChangedEvent
    ):
        """Handle OpenIDCConfig relation changed."""
        logging.debug("OpenIDCConfig relation changed")
        self.on.remote_ready.emit(event.relation)

    def get_keystone_info(self) -> dict[str, str]:
        keystone_data = {}
        if self.relations:
            # Should only be related to one keystone app
            relation = self.relations[0]
            keystone_data['ip'] = relation.data[relation.app].get("keystone_ip")
            keystone_data['port'] = relation.data[relation.app].get("keystone_port")
        return keystone_data

    def set_openidc_info(
        self, openidc_name: str, config_contents: str, ca=None
    ) -> None:
        """Set ceilometer configuration on the relation."""
        if not self.charm.unit.is_leader():
            logging.debug("Not a leader unit, skipping set config")
            return
        for relation in self.relations:
            relation.data[self.charm.app]["openidc-name"] = openidc_name
            relation.data[self.charm.app]["config-contents"] = base64.b64encode(config_contents.encode()).decode()
            if ca:
                relation.data[self.charm.app]["ca"] = base64.b64encode(ca.encode()).decode()

    @property
    def relations(self):
        return self.framework.model.relations[self.relation_name]

class OpenIDCConfigChangedEvent(RelationEvent):
    """OpenIDCConfigChanged Event."""

    pass


class OpenIDCConfigGoneAwayEvent(RelationBrokenEvent):
    """OpenIDCConfigGoneAway Event."""

    pass


class OpenIDCConfigRequirerEvents(ObjectEvents):
    """Events class for `on`."""

    config_changed = EventSource(OpenIDCConfigChangedEvent)
    goneaway = EventSource(OpenIDCConfigGoneAwayEvent)


class OpenIDCConfigRequires(Object):
    """OpenIDCConfigRequires class."""

    on = OpenIDCConfigRequirerEvents()

    def __init__(self, charm: CharmBase, relation_name: str, keystone_ip, keystone_port):
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.keystone_ip = keystone_ip
        self.keystone_port = keystone_port
        self.framework.observe(
            self.charm.on[relation_name].relation_changed,
            self._on_openidc_config_relation_changed,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken,
            self._on_openidc_config_relation_broken,
        )
        if self.charm.unit.is_leader():
            self.set_kestone_config()

    def set_kestone_config(self):
        for relation in self.relations:
            relation.data[self.charm.app]["keystone_ip"] = self.keystone_ip
            relation.data[self.charm.app]["keystone_port"] = self.keystone_port

    def _on_openidc_config_relation_changed(
        self, event: RelationChangedEvent
    ):
        """Handle OpenIDCConfig relation changed."""
        logging.debug("OpenIDCConfig config data changed")
        self.on.config_changed.emit(event.relation)

    def _on_openidc_config_relation_broken(
        self, event: RelationBrokenEvent
    ):
        """Handle OpenIDCConfig relation changed."""
        logging.debug("OpenIDCConfig on_broken")
        self.on.goneaway.emit(event.relation)

    def get_openidc_configs(self, exclude=None):
        exclude = exclude or []
        configs = []
        for relation in self.relations:
            if relation in exclude:
                continue
            try:
                openidc_name = relation.data[relation.app].get("openidc-name")
            except KeyError:
                logging.debug("Key error accessing app data")
                continue
            raw_config_contents = relation.data[relation.app].get("config-contents")
            if not all([openidc_name, raw_config_contents]):
                continue
            raw_ca = relation.data[relation.app].get("ca")
            config = {
                "openidc-name": openidc_name,
                "config-contents": base64.b64decode(raw_config_contents).decode()}
            if raw_ca:
                config["ca"] = base64.b64decode(raw_ca).decode()
            configs.append(config)
        return configs

    @property
    def relations(self):
        return self.framework.model.relations[self.relation_name]
