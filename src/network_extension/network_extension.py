##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import netaddr

from litp.core.extension import ModelExtension
from litp.core.model_type import ItemType, Property, PropertyType

from litp.core.litp_logging import LitpLogger

from netaddr import IPNetwork, IPAddress, AddrFormatError, NOHOST

from litp.core.validators import ItemValidator, ValidationError, \
    IntRangeValidator, NetworkValidator, PropertyValidator, \
    IPAddressValidator, IPv6AddressAndMaskValidator, \
    IntValidator

import litp.core.constants as constants

_LOG = LitpLogger()


class NetworkExtension(ModelExtension):
    """
    The LITP Network extension is used to model network interfaces (``eth``,
    ``bridge``, ``bond``, ``vlan``), their properties and relationships. It
    also models IPv4 and IPv6 network routes (``route``, ``route6``), virtual
    IPs (``vip``), and their properties.
    """

    FORWARDING_DELAY_MAX = 30
    FORWARDING_DELAY_MIN = 4
    FORWARDING_DELAY_DEFAULT = 4

    INT_MAX = 2147483647

    MULTICAST_HASH_SIZE_MAX = 2 ** 18

    MULTICAST_HASH_ELASTICITY_MAX = 4294967295

    ETH_BASE_REGEXP = r'[a-z][a-z0-9_]'

    @staticmethod
    def define_device_name_vlan_regexp():
        '''
        The VLAN device-name regexp is expected to match:
        eth0.1, eth0.11, eth0.111, eth.1111
        eth99.123, eth99.75
        eth0123456789.1
        eth0.1666, eth0.2444, eth0.3999, eth0.4075, eth0.4090, eth0.4094

        The regexp should *NOT* match:
        eth0.0, eth0.00, eth0.0000, eth0.01, eth0.001, eth0.0001, eth0.11111
        eth0123456789.11, eth0123456789.111, eth0123456789.1111
        eth012345678999.1, eth012345678999.11
        eth012345678999.111, eth012345678999.1111
        eth0.4099
        '''

        device_len13 = NetworkExtension.ETH_BASE_REGEXP + r'{1,12}'
        device_len12 = NetworkExtension.ETH_BASE_REGEXP + r'{1,11}'
        device_len11 = NetworkExtension.ETH_BASE_REGEXP + r'{1,10}'
        device_len10 = NetworkExtension.ETH_BASE_REGEXP + r'{1,9}'

        vlan_len1 = r'[1-9]'
        vlan_len2 = r'[1-9][0-9]{1}'
        vlan_len3 = r'[1-9][0-9]{2}'
        vlan_len4 = r'(([123][0-9]{3})|' + \
                     r'(40' + '[0-8][0-9])|' + \
                     r'(409' + '[01234]))'

        device_pattern = r'((' + device_len13 + r'\.' + vlan_len1 + r')|' + \
                          r'(' + device_len12 + r'\.' + vlan_len2 + r')|' + \
                          r'(' + device_len11 + r'\.' + vlan_len3 + r')|' + \
                          r'(' + device_len10 + r'\.' + vlan_len4 + r'))'

        regexp = r'^' + device_pattern + r'$'
        return regexp

    @staticmethod
    def _create_max_int_property_type(name):
        return NetworkExtension._add_numeric_property_type(
            name, 0,  NetworkExtension.INT_MAX)

    def define_property_types(self):

        property_types = []

        property_types.append(NetworkExtension._create_max_int_property_type(
            'ring_buffer_size_range'))

        property_types.append(
            NetworkExtension._create_max_int_property_type('arp_interval'))

        property_types.append(PropertyType('destination_network',
            regex=r"^[0-9./]+$",
            regex_error_desc='Value must be an IPv4 network',
            validators=[NetworkValidator()]
        ))

        property_types.append(PropertyType('destination_network_ipv6',
            regex=r"^[0-9a-fA-F:/]+$",
            regex_error_desc='Value must be an IPv6 network',
            validators=[Subnet6Validator()]
        ))

        property_types.append(PropertyType('ipv6_gateway_address',
            regex=r"^[0-9a-zA-Z:]+$",
            regex_error_desc='Value must be an IPv6 address',
            validators=[IPAddressValidator('6'), Gateway6Validator()]
        ))

        property_types.append(NetworkExtension._add_numeric_property_type(
            'seconds', NetworkExtension.FORWARDING_DELAY_MIN,
            NetworkExtension.FORWARDING_DELAY_MAX))

        # In order to allow vanity naming of interfaces, the regex should only
        # enforce device names acceptable to the kernel (between 1 and 16
        # lowercase chars and digits).
        #
        # Therefore, we shan't enforce conformance to either the old (eg. eth2)
        # or new (p4p2, em1) interface naming scheme.
        eth_name_regex = r'^(' + NetworkExtension.ETH_BASE_REGEXP + r'{0,14})$'

        property_types.append(PropertyType('device_name_generic',
            regex=eth_name_regex,
            regex_error_desc='Value must be a valid generic device name',
            validators=[DeviceNameLenValidator()]
        ))

        property_types.append(PropertyType('device_name_bridge',
            regex=r'^br[a-zA-Z0-9_]+$',
            regex_error_desc='Value must be a valid Bridge device name',
            validators=[DeviceNameLenValidator()]
        ))

        # TODO(xigomil) Unit test non-trivial experession
        # this is XSD regexp variant.
        property_types.append(PropertyType('device_name_vlan',
            regex=NetworkExtension.define_device_name_vlan_regexp(),
            regex_error_desc='Value must be a valid VLAN device name',
            validators=[DeviceNameLenValidator(),
                        VlanDeviceNameValidator()]
        ))

        property_types.append(PropertyType('bonding_mode',
            regex=r'^(0|balance-rr|'
                     '1|active-backup|'
                     '2|balance-xor|'
                     '3|broadcast|'
                     '4|802.3ad|'
                     '5|balance-tlb|'
                     '6|balance-alb)$',
            regex_error_desc='Value must be a valid Bond mode'
        ))

        property_types.append(PropertyType('bonding_primary_reselect',
            regex=r'^(0|always|'
                     '1|better|'
                     '2|failure)$',
            regex_error_desc='Value must be a valid Bond '
                             'primary reselection option'
        ))

        property_types.append(PropertyType('device_name_bond',
            regex=r'^bond[a-z0-9_]+$',
            regex_error_desc='Value must be a valid Bond device name'
        ))

        property_types.append(
            NetworkExtension._create_max_int_property_type('miimon'))

        property_types.append(
                        PropertyType("ipv4_or_ipv6_address_with_prefixlen",
                         validators=[IPAddressPrefixLenValidator()]))

        property_types.append(PropertyType('snooping_boolean_int',
            regex=r'^(0|1)$',
            regex_error_desc='Value must be 0 (disabled) or 1 (enabled)'
        ))

        property_types.append(PropertyType('arp_ip_target',
            regex=r"^[0-9\.,]+$",
            regex_error_desc='Value must be a valid IPv4 address or '
                             'up to 16 valid IPv4 addresses comma separated',
            validators=[ArpIpTargetsValidator()]
        ))

        property_types.append(PropertyType('arp_validate',
            regex=r'^(0|none|'
                     '1|active|'
                     '2|backup|'
                     '3|all)$',
            regex_error_desc='Value must be one of "none" or "0", '
                             '"active" or "1", "backup" or "2", '
                             '"all" or "3"',
        ))

        property_types.append(PropertyType('arp_all_targets',
            regex=r'^(any|0|all|1)$',
            regex_error_desc='Value must be one of "any" or "0",'
                             ' "all" or "1"',
            ))

        property_types.append(PropertyType('querier_boolean_int',
            regex=r'^(0|1)$',
            regex_error_desc='Value must be 0 (disabled) or 1 (enabled)'
        ))

        property_types.append(PropertyType('router_trivalue_int',
            regex=r'^(0|1|2)$',
            regex_error_desc='Value must be one of 0 (disabled), '
                             '1 (auto detect), or 2 (enabled)'
            ))

        property_types.append(PropertyType('hash_max_power_two_positive_int',
            regex=r"^[1-9][0-9]*$",
            regex_error_desc='Value must be a power of two '
                             'between 1 and %d' % \
                             NetworkExtension.MULTICAST_HASH_SIZE_MAX,
            validators=NetworkExtension.create_hash_max_vld8rs()
            ))

        property_types.append(PropertyType('hash_elasticity_int',
            regex=r"^[0-9]+$",
            regex_error_desc='Value must be an integer between 0 and %d' % \
                             NetworkExtension.MULTICAST_HASH_ELASTICITY_MAX,
            validators=[IntRangeValidator(
                    min_value=0,
                    max_value=NetworkExtension.MULTICAST_HASH_ELASTICITY_MAX)]
            ))

        property_types.append(NetworkExtension._create_max_int_property_type(
            'txqueuelen_range'))

        property_types.append(PropertyType(
            'xmit_hash_policy',
            regex=r'^(layer2|layer2\+3|layer3\+4)$',
            regex_error_desc='Value must be one of "layer2" or "layer2+3" '
                             'or "layer3+4"'
        ))

        return property_types

    @staticmethod
    def create_hash_max_vld8rs():
        vld8r1 = IntValidator()
        vld8r2 = PowerOfTwoValidator()

        max_val = NetworkExtension.MULTICAST_HASH_SIZE_MAX
        vld8r3 = IntRangeValidator(min_value=1, max_value=max_val)
        return [vld8r1, vld8r2, vld8r3]

    def define_item_types(self):
        item_types = []

        item_types.append(ItemType('eth',
            item_description='This item type represents'
                             ' an Ethernet network interface.',
            extend_item='network-interface',
            device_name=Property("device_name_generic",
                required=True,
                site_specific=True,
                prop_description="Device name for ethernet.",
                updatable_rest=False),
            macaddress=Property("mac_address",
                required=True,
                site_specific=True,
                prop_description="MAC address for device.",
                updatable_plugin=False,
                updatable_rest=True),
            bridge=Property("device_name_bridge",
                required=False,
                prop_description="Valid bridge name, if interface is "
                                 "part of the bridge."),
            master=Property("device_name_bond",
                required=False,
                updatable_rest=False,
                prop_description="Valid bond name, if interface is part "
                                 "of the bond."),
            pxe_boot_only=Property("basic_boolean",
                required=False,
                prop_description="Use this eth device as the PXE device."),
            rx_ring_buffer=Property("ring_buffer_size_range",
                required=False,
                prop_description="Use to configure reception buffer size."),
            tx_ring_buffer=Property("ring_buffer_size_range",
                required=False,
                prop_description="Use to configure transmission buffer size."),
            txqueuelen=Property('txqueuelen_range', required=False,
                updatable_rest=True,
                prop_description="Transmit Queue Length for the eth"),
            validators=[BridgedValidator(),
                        BondMasterEthValidator(),
                        PxeBootOnlyValidator()]
        ))

        item_types.append(ItemType('bridge',
            item_description='A bridge interface.',
            extend_item='network-interface',
            device_name=Property("device_name_bridge",
                site_specific=True,
                prop_description="Device name for bridge. Starts with 'br'",
                required=True,
                updatable_rest=False),
            stp=Property('basic_boolean',
                prop_description="Enable Spanning Tree Protocol.",
                default='false'),
            forwarding_delay=Property('seconds',
                prop_description=("Forwarding delay in seconds between "
                    "{0} and {1}.".format(
                    NetworkExtension.FORWARDING_DELAY_MIN,
                    NetworkExtension.FORWARDING_DELAY_MAX)),
                default="{0}".format(
                    NetworkExtension.FORWARDING_DELAY_DEFAULT)),
            multicast_snooping=Property('snooping_boolean_int',
                prop_description='Enable or disable multicast snooping',
                default='1',
                required=False,
                updatable_plugin=False,
                updatable_rest=True),
            multicast_querier=Property('querier_boolean_int',
                prop_description='Enable or disable multicast querier',
                default='0',
                required=False,
                updatable_plugin=False,
                updatable_rest=True),
            multicast_router=Property('router_trivalue_int',
                prop_description='This property allows you to specify if '
                                 'ports have multicast routers attached. A '
                                 'port with a multicast router will receive '
                                 'all multicast traffic. The default value '
                                 'for this property is 1, which allows the '
                                 'system to automatically detect the presence '
                                 'of routers. If the value is set to 2, ports '
                                 'will always receive all multicast traffic. '
                                 'A value of 0 disables this property '
                                 'completely.',
                default='1',
                required=False,
                updatable_plugin=False,
                updatable_rest=True),
            hash_max=Property('hash_max_power_two_positive_int',
                prop_description='Set the size of the multicast hash. '
                                 'The value must be a power of two '
                                 'between 1 and %d' % \
                                 NetworkExtension.MULTICAST_HASH_SIZE_MAX,
                default='512',
                required=False,
                updatable_plugin=False,
                updatable_rest=True),
            hash_elasticity=Property('hash_elasticity_int',
                prop_description='Number of hash table conflicts tolerated.',
                required=False,
                default='4',
                updatable_plugin=False,
                updatable_rest=True),
            validators=[RequiredInheritedPropertiesValidator(
                'bridge', ['network_name'])]
        ))

        item_types.append(ItemType('bond',
            item_description='This item type represents a network'
                             ' bond, which is a single interface'
                             ' that aggregates two or more'
                             ' Ethernet interfaces.',
            extend_item='network-interface',
            device_name=Property('device_name_bond',
                site_specific=True,
                prop_description="Device name for bond. Starts with 'bond'",
                required=True,
                updatable_rest=False),
            mode=Property('bonding_mode',
                prop_description='Bonding mode. '
                                 'Options are 0, 1, 2, 3, 4, 5, 6, '
                                 'balance-rr, active-backup, balance-xor, '
                                 'broadcast, 802.3ad, balance-tlb, '
                                 'balance-alb',
                required=False,
                default='1'),
            miimon=Property('miimon',
                prop_description='The Media Independent Interface '
                                 'link monitoring interval (in milliseconds)',
                required=False),
            arp_interval=Property('arp_interval',
                prop_description='Specifies the ARP link monitoring '
                                 'interval (in milliseconds)',
                required=False,
                updatable_rest=True,
                updatable_plugin=False),
            arp_ip_target=Property('arp_ip_target',
                prop_description='Specifies the IP addresses '
                                 'to use as ARP monitoring peers',
                required=False,
                updatable_rest=True,
                updatable_plugin=False),
            arp_validate=Property('arp_validate',
                prop_description='Specifies whether or not ARP probes and '
                                 'replies should be validated in any mode '
                                 'that supports ARP monitoring',
                required=False,
                updatable_rest=True,
                updatable_plugin=False),
            arp_all_targets=Property('arp_all_targets',
                prop_description='Specifies the quantity of arp_ip_targets '
                                 'that must be reachable in order for the ARP '
                                 'monitor to consider a slave as being up.',
                required=False,
                updatable_rest=True,
                updatable_plugin=False),
            bridge=Property("device_name_bridge",
                required=False,
                prop_description="Valid bridge name, if interface is "
                                 "part of the bridge."),
            primary=Property("device_name_generic",
                prop_description="Primary slave device name.",
                required=False,
                site_specific=True,
                updatable_rest=True,
                updatable_plugin=False),
            primary_reselect=Property('bonding_primary_reselect',
                prop_description='Bonding primary reselection. '
                                 'Options are 0, 1, 2, '
                                 'always, better, failure.',
                required=False,
                updatable_rest=True,
                updatable_plugin=False),
            xmit_hash_policy=Property(
                "xmit_hash_policy",
                required=False,
                updatable_rest=True,
                prop_description="Selects the transmit hash policy to use "
                                 "for slave selection in balance-xor and"
                                 "802.3ad modes. Possible values are one of"
                                 " layer2|layer3+4|layer2+3"),
            validators=[BridgedValidator(),
                        ArpPropertiesValidator(),
                        PrimaryValidator(),
                        XmitPolicyValidator()]
        ))

        item_types.append(ItemType('vlan',
            item_description="This item type represents a tagged"
                             " VLAN (Virtual Local Area Network)"
                             " interface.",
            extend_item='network-interface',
            device_name=Property('device_name_vlan',
                prop_description="Device name for VLAN",
                site_specific=True,
                required=True,
                updatable_rest=False),
            bridge=Property("device_name_bridge",
                required=False,
                prop_description="Valid bridge name, if interface is "
                                 "part of the bridge."),
            validators=[BridgedValidator(), VlanValidator()]
        ))

        item_types.append(ItemType('route',
            item_description='This item type represents'
                             ' a non-local IPv4 route',
            extend_item='route-base',
            subnet=Property('destination_network',
                site_specific=True,
                prop_description="Destination subnet for network route.",
                required=True),
            gateway=Property("ipv4_address",
                site_specific=True,
                prop_description="Destination gateway for network route.",
                required=True),
            validators=[NetworkRouteValidator()]
        ))

        item_types.append(ItemType('route6',
            item_description='This item type represents'
                             ' a non-local IPv6 route.',
            extend_item='route-base',
            subnet=Property('destination_network_ipv6',
                site_specific=True,
                prop_description="Destination subnet for network route.",
                required=True),
            gateway=Property("ipv6_gateway_address",
                site_specific=True,
                prop_description="Destination gateway for network route.",
                required=True)
            # Note: All remaining validation is done by property validators
            # attached to the subnet and gateway property types.
        ))

        item_types.append(ItemType('vip',
            item_description='This item type represents'
                             ' a virtual IP address.',
            network_name=Property(
                "basic_string",
                prop_description="Network the IP address(es) belongs to.",
                required=True
            ),
            ipaddress=Property(
                "ipv4_or_ipv6_address_with_prefixlen",
                site_specific=True,
                prop_description="IPv4 or IPv6 address with prefixlen",
                required=True
            )))

        return item_types

    @staticmethod
    def _add_numeric_property_type(name, min_val, max_val):
        return PropertyType(name,
            regex=r'^(([0-9])|([1-9][0-9]+))$',
            regex_error_desc='Value must be a positive integer',
            validators=[IntRangeValidator(min_val, max_val)]
        )

# ----- Custom Property validators -----


class XmitPolicyValidator(ItemValidator):
    def validate(self, properties):
        bonding_mode = properties.get('mode')
        prop_xmit_hash_policy = 'xmit_hash_policy'
        xmit_hash_policy = properties.get(prop_xmit_hash_policy)
        xmit_modes = ['2', 'balance-xor', '4', '802.3ad']
        if bonding_mode not in xmit_modes and xmit_hash_policy:
            msg = (
                'Property \'{0}\' can only be set if the bond mode is '
                'one of \'{1}\''.format(prop_xmit_hash_policy,
                                        ', '.join(xmit_modes))
            )
            return ValidationError(property_name=prop_xmit_hash_policy,
                                   error_message=msg)


class VlanDeviceNameValidator(PropertyValidator):
    """
    Validates VLAN ``device_name`` is conforming to IEEE 802.1q.
       - VLAN ID is a numeric value between 1 and 4094, inclusive
       - Device being tagged is not already tagged
    """

    def validate(self, property_value):

        VLAN_TAGID_MIN = 1
        VLAN_TAGID_MAX = 4094

        error_suffix = '"device_name" must have the format ' + \
                       '<device>.<VLAN ID>, maximum length 15 characters'

        try:
            tagged_dev, tag = property_value.rsplit(".", 1)
        except ValueError:
            return ValidationError(
                error_message='VLAN device_name must contain ' + \
                              '"." character. ' + error_suffix)

        if tagged_dev and ("." in tagged_dev):
            return ValidationError(
                error_message='VLAN Stacking is not currently supported. ' + \
                              error_suffix)

        if not tag or (tag and not tag.isdigit()):
            return ValidationError(
                error_message='VLAN ID must be a numeric value. '
                    + error_suffix)

        if tag and tag.isdigit() and \
           (VLAN_TAGID_MIN > int(tag) or int(tag) > VLAN_TAGID_MAX):
            return ValidationError(
                error_message=('VLAN ID must be a numeric value ' +
                               'between %d and %d. ' % \
                               (VLAN_TAGID_MIN, VLAN_TAGID_MAX)) + \
                               error_suffix)


class DeviceNameLenValidator(PropertyValidator):
    """
    Validated ``device_name`` is not longer than 15 characters.
    """

    def validate(self, property_value):
        DEV_NAME_MAX = 15
        if len(property_value) > DEV_NAME_MAX:
            return ValidationError(
                error_message="Device name must not be longer than %d "
                "characters." % (DEV_NAME_MAX))


# ----- Custom Item validators -----


class BondMasterEthValidator(ItemValidator):
    """
    Custom ItemValidator for ``eth`` items. Ensures that the ``master``
    property is not combined with any of the following properties: ``bridge``,
    ``network_name``, ``ipaddress`` or ``ipv6address``.
    """

    def validate(self, properties):
        master = properties.get('master')
        bridge = properties.get('bridge')
        ipaddress = properties.get('ipaddress')
        ip6address = properties.get('ipv6address')
        network_name = properties.get('network_name')

        if master and (ipaddress or ip6address or network_name or bridge):
            return ValidationError(property_name='master',
                   error_message='Properties "ipaddress"/"ipv6address" and '
                                 '"network_name" and "bridge" are not '
                                 'allowed if "master" is specified.')


class VlanValidator(ItemValidator):
    """
    Custom ItemValidator for ``vlan`` interface items. Ensures that the network
    interface contains a ``network_name`` if it is not a bridged interface.
    """
    def validate(self, properties):
        bridge = properties.get('bridge')
        network_name = properties.get('network_name')

        if not bridge and not network_name:
            return ValidationError(
                property_name='network_name',
                error_message='Property "network_name" is required on '
                'this item, if "bridge" property is not specified.')


class ArpPropertiesValidator(ItemValidator):
    """
    Custom ItemValidator for Bond items. This enforces the
    following constraints:
      - A bond can be configured to use either ``miimon`` or ARP monitoring
      - If configuring ARP monitoring:
          - ``mode`` must be set to one of 0 balance-rr, 1 active-backup,
            2 balance-xor, 3 broadcast
          - ``arp_interval`` and ``arp_ip_target`` properties are mandatory
          - ``arp_validate`` can only be set when ``mode`` is set to
            1 active-backup
          - ``arp_validate`` and ``arp_all_targets`` must always be specified
            together
    """
    @staticmethod
    def _arp_monitoring(properties):
        arp_prop_names = ['arp_interval', 'arp_ip_target',
                          'arp_validate', 'arp_all_targets']
        return any(properties.get(prop) for prop in arp_prop_names)

    def validate(self, properties):

        miimon = properties.get('miimon')

        if miimon and ArpPropertiesValidator._arp_monitoring(properties):
            msg = 'Properties "arp_interval", "arp_ip_target", ' \
                  '"arp_validate" and "arp_all_targets" are not ' \
                  'allowed if "miimon" is specified.'
            return ValidationError(property_name='miimon',
                                   error_message=msg)

        validate = properties.get('arp_validate')
        mode = properties.get('mode')

        if validate and mode not in ['1', 'active-backup']:
            msg = '"arp_validate" is only supported with "mode" property ' \
                  'set to "1" or "active-backup"'
            return ValidationError(property_name='mode',
                                   error_message=msg)

        if mode not in ['0', 'balance-rr',
                        '1', 'active-backup',
                        '2', 'balance-xor',
                        '3', 'broadcast'] and \
            ArpPropertiesValidator._arp_monitoring(properties):

            msg = 'ARP monitoring is only supported with "mode" property ' \
                  'set to one of the following: "0", "balance-rr", ' \
                  '"1", "active-backup", "2", "balance-xor", ' \
                  '"3", "broadcast"'

            return ValidationError(property_name='mode',
                                   error_message=msg)

        problem_property = None

        interval = properties.get('arp_interval')
        ip_target = properties.get('arp_ip_target')

        if interval and not ip_target:
            problem_property = 'arp_interval'
        elif ip_target and not interval:
            problem_property = 'arp_ip_target'

        if problem_property:
            msg = 'Properties "arp_interval" and "arp_ip_target" ' \
                  'must both be specified.'
            return ValidationError(property_name=problem_property,
                                   error_message=msg)

        all_targets = properties.get('arp_all_targets')
        problem_property = None

        if validate and not interval:
            problem_property = 'arp_validate'
        elif all_targets and not interval:
            problem_property = 'arp_all_targets'

        if problem_property:
            msg = ('Properties "arp_interval" and "arp_ip_target" '
                   'must be specified when using "%s"') % problem_property
            return ValidationError(property_name=problem_property,
                                   error_message=msg)

        problem_property = None

        if validate and not all_targets:
            problem_property = 'arp_validate'
        elif all_targets and not validate:
            problem_property = 'arp_all_targets'

        if problem_property:
            msg = 'Properties "arp_validate" and "arp_all_targets" ' \
                  'must both be specified.'
            return ValidationError(property_name=problem_property,
                                   error_message=msg)


class PxeBootOnlyValidator(ItemValidator):
    """
    Custom ItemValidator for ``eth`` item type. Ensures that the properties
    ``ipaddress``, ``network_name``, ``bridge`` or ``bond`` are not set
    if the ``pxe_boot_only`` property is set to ``true``.
    """
    def validate(self, properties):
        pxe_boot_only = properties.get('pxe_boot_only')
        bridge = properties.get('bridge')
        bond = properties.get('master')
        ipaddress = properties.get('ipaddress')
        ip6address = properties.get('ipv6address')
        network_name = properties.get('network_name')
        if pxe_boot_only == 'true' and (ip6address or ipaddress or
                network_name or bridge or bond):
            msg = ('Properties "ipaddress"/"ipv6address", "network_name", '
                   '"bridge" and "bond" are not allowed when '
                   '"pxe_boot_only" property is set to "true"')
            return ValidationError(property_name='pxe_boot_only',
                                   error_message=msg)


class PrimaryValidator(ItemValidator):
    """
    Custom ItemValidator for Bond interface items. Ensures that the
    primary and primary_reselect properties are both set together,
    and only set with the correct bond mode.
    """

    def validate(self, properties):
        mode = properties.get('mode')
        primary = properties.get('primary')
        reselect = properties.get('primary_reselect')

        problem_property = None

        if primary and not reselect:
            problem_property = 'primary'
        elif reselect and not primary:
            problem_property = 'primary_reselect'

        if problem_property:
            msg = 'Properties "primary" and "primary_reselect" ' \
                  'must both be specified.'
            return ValidationError(property_name=problem_property,
                                   error_message=msg)

        allowed_modes = ['1', '5', '6',
                         'active-backup', 'balance-tlb', 'balance-alb']

        if primary and reselect and mode not in allowed_modes:
            msg = ('Properties "primary" and "primary_reselect" may only be ' \
                   'set when property "mode" is set to one of %s') % \
                   ', '.join(allowed_modes)
            return ValidationError(property_name='mode',
                                   error_message=msg)


class BridgedValidator(ItemValidator):
    """
    Custom ItemValidator for interface items. Ensures that the network
    interface does not contain IP-related properties if it is a bridged
    interface.
    """

    def validate(self, properties):
        bridge = properties.get('bridge')
        ipaddress = properties.get('ipaddress')
        ip6address = properties.get('ipv6address')
        network_name = properties.get('network_name')

        if bridge and (ipaddress or network_name or ip6address):
            return ValidationError(
                property_name='bridge',
                error_message='Properties "ipaddress"/"ipv6address" and '
                '"network_name" are not allowed if "bridge" is specified.')
        if not bridge and (ipaddress or ip6address) and not network_name:
            return ValidationError(
                property_name='network_name',
                error_message='Property "network_name" is required on '
                'this item, if "bridge" property is not specified and '
                '"ipaddress" or "ipv6address" property is specified.')


class NetworkNamePresentValidator(ItemValidator):
    """
    Custom ItemValidator for bond Items ensuring if ``ipaddress`` and/or
    ``ipv6address`` is specified ``network_name`` must also be specified.
    """

    def validate(self, properties):
        ipaddress = properties.get('ipaddress')
        ip6address = properties.get('ipv6address')
        network_name = properties.get('network_name')
        if (ipaddress or ip6address) and not network_name:
            return ValidationError(
                property_name='network_name',
                error_message='Property "network_name" is required on '
                'this item, if "ipaddress" or "ipv6address" property '
                'is specified.')


class RequiredInheritedPropertiesValidator(ItemValidator):
    """
    Custom set of inherited properties that are required on this item.
    """

    def __init__(self, item_type_id, required_properties):
        self.item_type_id = item_type_id
        self.required_properties = required_properties
        super(RequiredInheritedPropertiesValidator, self).__init__()

    def validate(self, properties):
        for prop in self.required_properties:
            if prop not in properties or not properties.get(prop):
                msg = ('ItemType "%s" is required to have a '
                    'property with name "%s"' % (self.item_type_id, prop))
                return ValidationError(
                    property_name=prop,
                    error_message=msg,
                    error_type=constants.MISSING_REQ_PROP_ERROR)


class NetworkRouteValidator(ItemValidator):
    """
    Custom ItemValidator for ``route`` item type.

    Validates following constraints:
        - Netmask must be specified
        - ``gateway`` property must not be multicast address
        - ``gateway`` address must not be part of route's subnet
          (Except when subnet is default, "0.0.0.0/0")
    """

    def validate(self, properties):
        """
        Validates following constraints:
            - Netmask must be specified
            - ``gateway`` property must not be multicast address
            - ``gateway`` address must not be part of route's subnet
              (Except when subnet is default, "0.0.0.0/0")
        """

        # The validation step that ensures the required properties on a route
        # item are actually present *may not* have been performed by the time
        # this validator is called. Therefore, we need to bail if both
        # properties aren't present.
        if not ('subnet' in properties and 'gateway' in properties):
            return None

        property_name = 'subnet'
        subnet_spec = properties.get(property_name)
        if '/' not in subnet_spec:
            return ValidationError(
                property_name=property_name,
                error_message="Netmask must be specified")

        route_subnet = None
        gateway_address = None

        try:
            route_subnet = IPNetwork(subnet_spec, implicit_prefix=False)
            gateway_string = properties.get('gateway')
            if '/' in gateway_string:
                return ValidationError(
                    property_name='gateway',
                    error_message="Gateway address {0}"
                        " cannot have netmask.".format(gateway_string)
                        )
            gateway_address = IPAddress(gateway_string)
        except AddrFormatError:
            # PropertyValidators will have already reported errors
            return None

        property_name = 'gateway'
        # Can't have a multicast address as gateway!
        if gateway_address.is_multicast():
            return ValidationError(
                    property_name=property_name,
                    error_message="Cannot use multicast address {0} as"
                        " gateway".format(gateway_address))

        # Can't have a gateway address part of the route's subnet
        if route_subnet != IPNetwork('0.0.0.0/0') and \
                gateway_address in route_subnet:
            return ValidationError(
                    property_name=property_name,
                    error_message="The gateway address {0} cannot lie within "
                        "the route's subnet {1}".format(
                            gateway_address, route_subnet))


class Gateway6Validator(PropertyValidator):
    """
    Validates extra constraints an IPv6 address has when it is a
    ``gateway`` property within a ``route6`` item.
    """
    def validate(self, property_value):

        if property_value == '':
            return ValidationError(
                property_name='gateway',
                error_message="Gateway cannot be empty.")

        if not property_value:
            return None

        gateway_string = property_value
        if '/' in gateway_string:
            return ValidationError(
                property_name='gateway',
                error_message="Gateway address {0}"
                    " cannot have netmask.".format(gateway_string)
                    )

        try:
            gateway_address = IPAddress(gateway_string)
        except AddrFormatError:
            # PropertyValidators will have already reported errors
            return None

        # Can't have a multicast address as gateway!
        if gateway_address.is_multicast():
            return ValidationError(
                    property_name='gateway',
                    error_message='Cannot use multicast address {0} as'
                        ' gateway'.format(gateway_string))

        # Gateway cannot be local loopback
        if gateway_address.is_loopback():
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be local loopback.'.format(gateway_string)
                )

        # Gateway cannot be 'undefined' address
        if gateway_address == IPAddress('::'):
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be the undefined address.'.format(gateway_string)
                )

        # Gateway cannot be link local
        if gateway_address.is_link_local():
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be link-local.'.format(gateway_string)
                    )

        if gateway_address.is_reserved():
            return ValidationError(
                property_name='gateway',
                error_message='The gateway address {0} '
                    'cannot be reserved.'.format(gateway_string)
                )


class Subnet6Validator(PropertyValidator):
    """
    Validates the property's value is a valid IPv6 Route Subnet.
        - Cannot be a multicast address
        - Cannot be a reserved network
        - For non-default (i.e. not "::/0") routes prefix
          length cannot be zero
        - Cannot be a link-local address
        - Cannot be local loopback address
        - Cannot have host bits set
        - Must include prefix length
    """
    def validate(self, property_value):

        if property_value == '':
            return ValidationError(error_message="Subnet cannot be empty.")

        if not property_value:
            return None

        try:
            net = netaddr.IPNetwork(
                property_value,
                version=6,
                implicit_prefix=False,
                flags=NOHOST
                )
            if net.is_multicast():
                return ValidationError(
                        error_message="Subnet cannot be a multicast address.",
                    )
            if net.is_reserved():
                return ValidationError(
                        error_message="Subnet cannot be a reserved network.",
                    )

            # Prefix ::/0 can be used just for default GW.
            if property_value.endswith('::/0') and property_value != '::/0':
                return ValidationError(
                    error_message='Routing destination \'{0}::\' cannot '
                          'have prefix length 0, because it is reserved '
                          'for the default route '
                          'only (::/0).'.format(
                            property_value.split('::/0')[0]
                            )
                          )

            # IPNetwork('::1').is_loopback() does't work..
            if IPAddress(property_value.split('/')[0]).is_loopback():
                return ValidationError(
                        error_message="Subnet cannot be loopback."
                        )

            # Route address cannot be link-local.
            if net.ip.is_link_local():
                return ValidationError(
                    error_message='Cannot use link-local address {0} '
                        'as subnet.'.format(net)
                        )

        except netaddr.AddrFormatError:
            return ValidationError(
                error_message="Invalid IPv6 subnet value '%s'"
                    % str(property_value))
        except Exception as e:
            return ValidationError(
                error_message="Invalid value: %s" % str(e))

        if not '/' in property_value:
            return ValidationError(
                error_message="Subnet must include prefix length"
                )


class ArpIpTargetsValidator(PropertyValidator):
    '''
    This is a validator to check whether an ``arp_ip_target`` property
    is formatted correctly. ``arp_ip_target`` must be a single valid
    IPv4 address or up to 16 valid IPv4 addresses comma separated without
    any duplicate addresses.
    '''

    def validate(self, property_value):

        tokens = []

        if ',' in property_value:
            tokens = property_value.split(',')
        else:
            tokens.append(property_value)

        validation_errs = ''

        validation_errs += self._check_duplicate_addresses(tokens)
        validation_errs += self._check_number_of_ipaddresses(tokens)
        validation_errs += self._check_malformed_ip_addresses(
                                                  tokens, property_value)

        if validation_errs:
            return ValidationError(error_message=validation_errs)

    @staticmethod
    def _check_duplicate_addresses(tokens):
        err_msg = ''

        duplicate_ip_addresses = list(set([addr for addr in tokens
                                           if tokens.count(addr) > 1]))

        if duplicate_ip_addresses:
            duplicates_str = ', '.join(duplicate_ip_addresses)
            err_msg = "Duplicate IP addresses are not permitted - '{0}'. "
            err_msg = err_msg.format(duplicates_str)
        return err_msg

    @staticmethod
    def _check_number_of_ipaddresses(tokens):
        err_msg = ''

        if len(tokens) > 16:
            err_msg = "Too many IPv4 addresses in address list. "

        return err_msg

    @staticmethod
    def _check_malformed_ip_addresses(tokens, property_value):

        err_msg = ''

        validator = IPAddressValidator("4")

        malformed_ip_addresses = [addr for addr in tokens
                                  if validator.validate(addr)
                                  is not None]

        if malformed_ip_addresses:
            err_msg = ("Invalid IP address(es) in '%s'. "
                                     % str(property_value))
        return err_msg


class IPAddressPrefixLenValidator(PropertyValidator):
    '''
    This validator is used to check whether a property is a valid IPv4 or IPv6
    address. For an IPv6 address, the validator accepts as valid a value
    expressed as address/prefix_len (CIDR) format, or a value without a
    prefix_len.
    '''

    def validate(self, property_value):
        split_out = property_value.split('/', 1)
        address = split_out[0]
        try:
            ip = IPAddress(address)
        except (AddrFormatError, ValueError):
            return ValidationError(
                error_message="Invalid IP address value '%s'"
                    % str(property_value))

        if ip.version == 6:
            _validator = IPv6AddressAndMaskValidator()
        else:
            _validator = IPAddressValidator('4')

        return _validator.validate(property_value)


class PowerOfTwoValidator(PropertyValidator):
    '''
    This is a validator to check whether a property value
    is a power of two positive integer.
    '''

    def validate(self, property_value):

        num = 0
        try:
            num = int(property_value)
        except ValueError:
            # This should be dealt with by the IntValidator validator
            return None

        is_power2 = (num > 0) and not (num & (num - 1))

        if not is_power2:
            msg = ('Property value "%s" is not a power of two '
                   'between 1 and %d' %
                   (property_value, NetworkExtension.MULTICAST_HASH_SIZE_MAX))
            return ValidationError(property_name='hash_max',
                                   error_message=msg)
