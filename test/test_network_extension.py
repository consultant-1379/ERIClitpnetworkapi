##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest

from litp.core.validators import IPAddressValidator
from nose.tools import nottest

from network_extension.network_extension import (NetworkExtension,
                                                 NetworkRouteValidator,
                                                 BridgedValidator,
                                                 VlanValidator,
                                                 RequiredInheritedPropertiesValidator,
                                                 VlanDeviceNameValidator,
                                                 DeviceNameLenValidator,
                                                 NetworkNamePresentValidator,
                                                 BondMasterEthValidator,
                                                 IPAddressPrefixLenValidator,
                                                 Subnet6Validator,
                                                 Gateway6Validator,
                                                 ArpIpTargetsValidator,
                                                 ArpPropertiesValidator,
                                                 PowerOfTwoValidator,
                                                 PxeBootOnlyValidator,
                                                 XmitPolicyValidator)

from litp.extensions.core_extension import CoreExtension
from litp.core.plugin_context_api import PluginApiContext
from litp.extensions.core_extension import CoreExtension
from litp.core.execution_manager import ExecutionManager
from litp.core.plugin_manager import PluginManager
from litp.core.model_manager import ModelManager
from litp.core.model_type import (ItemType, Child,
                                  RefCollection, Collection)

from litp.core.validators import ValidationError

import litp.core.constants as constants


class TestNetworkExtension(unittest.TestCase):

    def setUp(self):

        self.route_validator = NetworkRouteValidator()
        self.bridged_validator = BridgedValidator()
        self.vlan_validator = VlanValidator()
        self.req_inherited_props_validator = \
            RequiredInheritedPropertiesValidator(
                'item_type_id', ['network_name'])
        self.vlan_name_validator = VlanDeviceNameValidator()
        self.dev_name_len_validator = DeviceNameLenValidator()
        self.bond_master_eth_validator = BondMasterEthValidator()
        self.vip_validator = IPAddressPrefixLenValidator()
        self.network_name_validator = NetworkNamePresentValidator()

        self.model = ModelManager()
        self.validator = self.model.validator
        self.plugin_manager = PluginManager(self.model)
        self.context = PluginApiContext(self.model)

        self.core = CoreExtension()
        self.plugin_manager.add_property_types(
            self.core.define_property_types())
        self.plugin_manager.add_item_types(self.core.define_item_types())
        self.plugin_manager.add_default_model()

        self.api = NetworkExtension()
        self.plugin_manager.add_property_types(self.api.define_property_types())
        self.plugin_manager.add_item_types(self.api.define_item_types())

        # Cache these item and property types in test setup for quick reference

        self.property_types = dict(
            (x.property_type_id, x) for x in self.api.define_property_types())

        self.item_types = dict(
            (x.item_type_id, x) for x in self.api.define_item_types())

    def tearDown(self):
        pass

    def _mock_root_and_node_types(self):
        self.model_manager = ModelManager()
        self.model_manager.register_property_types(
            CoreExtension().define_property_types())
        self.model_manager.register_item_types(
            CoreExtension().define_item_types())

        self.model_manager.item_types.pop('root')
        self.model_manager.item_types.pop('node')

        self.model_manager.register_item_type(ItemType('node',
            network_interfaces=Collection('network-interface'),
            routes=RefCollection('route')))

        self.model_manager.register_item_type(ItemType('root',
            networks=Collection('network'),
            node=Child('node'),
            routes=Collection('route-base')))

        # add types from this extension
        self.model_manager.register_property_types(
            self.api.define_property_types())
        self.model_manager.register_item_types(
            self.api.define_item_types())

    def test_property_types_registered(self):
        expected = set([
             "arp_interval", 'seconds', 'bonding_mode', "miimon",
             'device_name_generic', 'device_name_bond',
             'device_name_bridge', 'device_name_vlan',
             'destination_network', 'destination_network_ipv6',
             'ipv4_or_ipv6_address_with_prefixlen',
             'ipv6_gateway_address', 'snooping_boolean_int',
             'router_trivalue_int', 'querier_boolean_int',
             'hash_max_power_two_positive_int', 'hash_elasticity_int',
             'arp_ip_target', 'arp_validate', 'arp_all_targets',
             'bonding_primary_reselect', "ring_buffer_size_range",
             'txqueuelen_range', 'xmit_hash_policy'])

        actual = set([pt.property_type_id for pt in
                      self.api.define_property_types()])

        difference = actual.difference(expected)
        message = "difference between actual and expected {0}".format(
            difference)
        self.assertEquals(actual, expected, message)

    def test_item_types_registered(self):
        itypes_expected = set(
            ['eth', 'bridge', 'bond', 'route', 'route6', 'vip', 'vlan'])
        itypes = set([it.item_type_id for it in
                      self.api.define_item_types()])
        self.assertEquals(itypes_expected, itypes)

    def _test_property_type(self, ptype, expected_validation_results):

        pname = "test_property_name"
        message = "expected {0} validation error for value '{1}'\nactual = {2}"
        ptype_object = self.property_types.get(ptype)

        for value, expected in expected_validation_results:

            actual = self.validator._run_property_type_validators(
                ptype_object, pname, value)

            if expected is not None:
                self.assertEquals(
                    len(actual), 1, message.format(1, value, actual))
                expected_validation_error = ValidationError(
                    property_name=pname, error_message=expected)
                self.assertEquals(actual[0], expected_validation_error)
            else:
                self.assertEquals(
                    len(actual), 0, message.format(0, value, actual))

    def test_ring_buffer_size_range_property_type_validation(self):

        range_error = "Value outside range 0 - {0}"
        regex_error = "Invalid value '{0}'. Value must be a positive integer"

        good_value   = "{0}".format(int(NetworkExtension.INT_MAX * 0.5))
        leading_zero = "0{0}".format(good_value)
        too_small    = "-1"
        too_big      = "{0}".format(NetworkExtension.INT_MAX + 1)

        expected = [
            (too_small,    regex_error.format(too_small)),
            (good_value,   None),
            ("abc",        regex_error.format("abc")),
            (leading_zero, regex_error.format(leading_zero)),
            ("123",        None),
            ("3av2",       regex_error.format("3av2")),
            (too_big,      range_error.format(NetworkExtension.INT_MAX))
        ]

        self._test_property_type("ring_buffer_size_range", expected)

    def test_txqueuelen_range_property_type_validation(self):

        range_error = "Value outside range 0 - {0}"
        regex_error = "Invalid value '{0}'. Value must be a positive integer"

        good_value = "{0}".format(int(NetworkExtension.INT_MAX * 0.5))
        leading_zero = "0{0}".format(good_value)
        too_small = "-1"
        too_big = "{0}".format(NetworkExtension.INT_MAX + 1)

        expected = [
            (too_small,    regex_error.format(too_small)),
            (good_value,   None),
            ("abc",        regex_error.format("abc")),
            (leading_zero, regex_error.format(leading_zero)),
            ("123",        None),
            ("3av2",       regex_error.format("3av2")),
            (too_big,      range_error.format(NetworkExtension.INT_MAX))
        ]

        self._test_property_type("txqueuelen_range", expected)

    def test_xmit_hash_policy_regex(self):
        regex_error = 'Invalid value \'{0}\'. Value must be one of "layer2"' \
                      ' or "layer2+3" or "layer3+4"'

        def _assert_regex_error(bad_values):
            expected = []
            for value in bad_values:
                expected.append((
                    value, regex_error.format(value)
                ))
            self._test_property_type("xmit_hash_policy", expected)

        def _assert_no_regex_error(values):
            expected = []
            for value in values:
                expected.append((value, None))
            self._test_property_type("xmit_hash_policy", expected)

        _assert_regex_error(
                ['layer', 'ayer2', 'layer2+', 'layer3', 'layer3+', 'layer2a',
                 'layer23', 'layer21z', 'encap', 'ncap2', 'encap2+', 'encap3',
                 'encap3+', 'encap2a', 'encap23', 'encap21z', 'abc', '123',
                 '', '*', 'layer2+3|encap3+4', 'encap2', 'encap2+3',
                 'encap3+4'])

        _assert_no_regex_error(
                ['layer2', 'layer2+3', 'layer3+4'])

    def test_xmit_hash_policy_validation(self):
        validator = XmitPolicyValidator()
        prop_xmit_hash_policy = 'xmit_hash_policy'

        properties = {
            'mode': '1'
        }
        self.assertEqual(
            None, validator.validate(properties),
            msg='No validation error is expected when non-policy bonding mode'
                ' is set and {0} is not.'.format(prop_xmit_hash_policy))

        properties['mode'] = '2'
        self.assertEqual(None, validator.validate(properties))
        self.assertEqual(
            None, validator.validate(properties),
            msg='No validation error is expected when policy bonding mode '
                'is set and {0} is not.'.format(prop_xmit_hash_policy))

        invalid_modes = [
            '0', '1', '3', '5', '6',
            'balance-rr', 'active-backup', 'broadcast', 'balance-tlb',
            'balance-alb'
        ]
        properties[prop_xmit_hash_policy] = 'layer2'

        for mode in invalid_modes:
            properties['mode'] = mode
            error = validator.validate(properties)
            self.assertNotEqual(
                None, error,
                msg='Expected a validation error when {0} is set and '
                    'bonding mode is {1}'.format(prop_xmit_hash_policy, mode))

        valid_modes = ['2', 'balance-xor', '4', '802.3ad']
        for mode in valid_modes:
            properties['mode'] = mode
            error = validator.validate(properties)
            self.assertEqual(
                None, error,
                msg='No validation error is expected when {0} is set and '
                    'bonding mode is {1}'.format(prop_xmit_hash_policy, mode))

    def test_bridged_interface_has_l3_data(self):
        expected_error1 = ValidationError(
            property_name='bridge',
            error_message='Properties "ipaddress"/"ipv6address" and '
            '"network_name" are not allowed if "bridge" is specified.')

        expected_error2 = ValidationError(
            property_name='network_name',
            error_message='Property "network_name" is required on this '
            'item, if "bridge" property is not specified and '
            '"ipaddress" or "ipv6address" property is specified.')

        bad_props = {'bridge': 'br0', 'network_name': 'foo'}
        error = self.bridged_validator.validate(bad_props)
        self.assertEquals(expected_error1, error)

        bad_props = {'bridge': None, 'network_name': None,
                         'ipaddress': '1.2.3.4'}
        error = self.bridged_validator.validate(bad_props)
        self.assertEquals(expected_error2, error)

        good_props = {'bridge': 'br0', 'network_name': None, 'ipaddress': None}
        error = self.bridged_validator.validate(good_props)
        self.assertEquals(None, error)

        good_props = {'bridge': None, 'network_name': 'bar', 'ipaddress': None}
        error = self.bridged_validator.validate(good_props)
        self.assertEquals(None, error)

        good_props = {'bridge': 'br0', 'network_name': None, 'ipv6address': None}
        error = self.bridged_validator.validate(good_props)
        self.assertEquals(None, error)

        good_props = {'bridge': None, 'network_name': 'bar', 'ipv6address': None}
        error = self.bridged_validator.validate(good_props)
        self.assertEquals(None, error)

        bad_props = {'bridge': 'br0', 'ipv6address': '::127/64'}
        error = self.bridged_validator.validate(bad_props)
        self.assertEquals(expected_error1, error)

    def test_vlan_has_network_if_not_bridged(self):
        expected_error1 = ValidationError(
            property_name='network_name',
                error_message='Property "network_name" is required on '
                'this item, if "bridge" property is not specified.')

        bad_props = {'vlan': 'vlan.123', 'network_name': None}
        error = self.vlan_validator.validate(bad_props)
        self.assertEquals(expected_error1, error)

    def test_req_inherited_properties(self):
        expected_error = ValidationError(
            property_name='network_name',
            error_message='ItemType "item_type_id" is required to have a property with name "network_name"',
            error_type=constants.MISSING_REQ_PROP_ERROR)

        bad_bridge_props = {'network_name': None}
        error = self.req_inherited_props_validator.validate(bad_bridge_props)
        self.assertEquals(expected_error, error)

        good_bridge_props = {'network_name': 'foo'}
        error = self.req_inherited_props_validator.validate(good_bridge_props)
        self.assertEquals(None, error)

    def test_route_item_no_properties(self):
        self.assertEquals(None, self.route_validator.validate({}))

    def test_route_item_malformed_destination(self):
        bad_dest_route_props = {
                'subnet': '10.11.12.0 netmask 255.255.255.0',
                'gateway': '192.168.1.45',
            }
        expected_validation_error = ValidationError(
                property_name='subnet',
                error_message='Netmask must be specified'
            )
        self.assertEquals(
                expected_validation_error,
                self.route_validator.validate(bad_dest_route_props)
            )

    def test_route_item_malformed_gateway(self):
        bad_dest_route_props = {
                'subnet': '10.11.12.0/24',
                'gateway': '192.168.1.545',
            }

        self._mock_root_and_node_types()
        self.model_manager.create_root_item('root', '/')
        route = self.model_manager.create_item(
                'route',
                '/routes/def',
                **bad_dest_route_props
            )

        self.assertEquals(
                [ValidationError(
                        property_name='gateway',
                        error_message='Invalid IPAddress value \'192.168.1.545\'',
                    )],
                route
            )

        # We shouldn't get a ValidationError from the Route item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEquals(
                None,
                self.route_validator.validate(bad_dest_route_props)
            )

    def test_route_item_mcast_gateway(self):
        bad_dest_route_props = {
                'subnet': '10.11.12.0/24',
                'gateway': '235.11.12.13',
            }

        # We shouldn't get a ValidationError from the Route item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='Cannot use multicast address '
                        '235.11.12.13 as gateway',
                    ),
                self.route_validator.validate(bad_dest_route_props)
            )

    def test_route_item_gateway_in_dest(self):
        bad_dest_route_props = {
                'subnet': '10.11.12.0/24',
                'gateway': '10.11.12.13',
            }

        # We shouldn't get a ValidationError from the Route item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address 10.11.12.13 cannot '
                            'lie within the route\'s subnet 10.11.12.0/24',
                    ),
                self.route_validator.validate(bad_dest_route_props)
            )

    def test_netmask_in_ipv4_gateway(self):
        bad_dest_route_props = {
                'subnet': '10.11.12.0/24',
                'gateway': '192.168.0.1/16',
            }
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='Gateway address 192.168.0.1/16 cannot have netmask.'
                    ),
                self.route_validator.validate(bad_dest_route_props)
            )

    def test_network_name_validator(self):
        item = {'ipaddress': '1.2.3.4', 'network_name': 'foo'}
        self.assertEquals(None, self.network_name_validator.validate(item))
        item = {'ipaddress': None, 'network_name': 'foo'}
        self.assertEquals(None, self.network_name_validator.validate(item))
        item = {'ipv6address': '2001::127', 'network_name': 'foo'}
        self.assertEquals(None, self.network_name_validator.validate(item))
        item = {'ipv6address': None, 'network_name': 'foo'}
        self.assertEquals(None, self.network_name_validator.validate(item))
        error = ValidationError(
            property_name='network_name',
            error_message='Property "network_name" is required on this item, '
            'if "ipaddress" or "ipv6address" property is specified.')
        item = {'ipaddress': '1.2.3.4', 'network_name': None}
        self.assertEquals(error, self.network_name_validator.validate(item))
        item = {'ipv6address': '2001::127', 'network_name': None}
        self.assertEquals(error, self.network_name_validator.validate(item))

    def test_vlan_device_name_valid(self):
        self.assertEquals(None, self.vlan_name_validator.validate('eth0.123'))
        self.assertEquals(None, self.vlan_name_validator.validate('eth3.321'))
        self.assertEquals(None, self.vlan_name_validator.validate('123.123'))

    @property
    def _vlan_error_suffix(self):
        return '"device_name" must have the format ' + \
               '<device>.<VLAN ID>, maximum length 15 characters'

    def test_vlan_device_name_not_int(self):
        error = ValidationError(error_message='VLAN ID must be a numeric value. ' +  self._vlan_error_suffix)
        self.assertEquals(error, self.vlan_name_validator.validate('eth0.foo'))

        error = ValidationError(error_message='VLAN ID must be a numeric value. ' + self._vlan_error_suffix)
        self.assertEquals(error, self.vlan_name_validator.validate('eth1.-1'))

        error = ValidationError(error_message='VLAN ID must be a numeric value. ' + self._vlan_error_suffix)
        self.assertEquals(error, self.vlan_name_validator.validate('eth0.'))
        self.assertEquals(error, self.vlan_name_validator.validate('123.'))

    def test_vlan_device_name_no_nested_tags(self):
        error = ValidationError(error_message='VLAN Stacking is not currently supported. ' + self._vlan_error_suffix)
        self.assertEquals(error, self.vlan_name_validator.validate('eth0.f.o.o'))

    def test_vlan_device_name_not_in_range(self):
        error = ValidationError(error_message='VLAN ID must be a numeric value between 1 and 4094. ' + self._vlan_error_suffix)
        self.assertEquals(error, self.vlan_name_validator.validate('eth0.0'))
        self.assertEquals(error, self.vlan_name_validator.validate('eth0.9999'))
        self.assertEquals(error, self.vlan_name_validator.validate('eth0.99999'))  # > 15 chars

    def test_vlan_device_name_empty(self):
        error = ValidationError(error_message='VLAN device_name must contain "." character. ' + self._vlan_error_suffix)
        self.assertEquals(error, self.vlan_name_validator.validate('eth0'))

    def test_device_name_len(self):
        self.assertEquals(None, self.dev_name_len_validator.validate('eth4567890.2345'))
        error = ValidationError(error_message='Device name must not be longer than 15 characters.')
        self.assertEquals(error, self.dev_name_len_validator.validate('eth4567890.23456'))

    def test_bond_master_eth_validator(self):
        properties = {}
        self.assertEquals(None, self.bond_master_eth_validator.validate(properties))

        # ----
        properties = {'master': 'bond0'}
        self.assertEquals(None, self.bond_master_eth_validator.validate(properties))

        # ----
        error = ValidationError(property_name='master',
                    error_message='Properties "ipaddress"/"ipv6address" '
                                  'and "network_name" and "bridge" are not '
                                  'allowed if "master" is specified.')

        for prop_name in ['ipaddress', 'ipv6address', 'network_name', 'bridge']:
            properties = {'master': 'bond0', prop_name: 'X'}
            self.assertEquals(error, self.bond_master_eth_validator.validate(properties))

    def test_vip_address_validator(self):
        self.assertEquals(None, self.vip_validator.validate('1.2.3.4'))
        self.assertEquals(None, self.vip_validator.validate('2607:f0d0:1002:51::4/120'))
        self.assertEquals(None, self.vip_validator.validate('2607:f0d0:1002:51::4'))

        error = ValidationError(error_message="IPv6 address '2607:f0d0:1002:51::4/pepefix' is not valid")
        self.assertEquals(error, self.vip_validator.validate('2607:f0d0:1002:51::4/pepefix'))

        error = ValidationError(error_message="Invalid IP address value 'pepeip'")
        self.assertEquals(error, self.vip_validator.validate('pepeip'))

        error = ValidationError(error_message="Invalid IPAddress value '1.2.3.4/120'")
        self.assertEquals(error, self.vip_validator.validate('1.2.3.4/120'))

        error = ValidationError(error_message="Invalid IP address value '/'")
        self.assertEquals(error, self.vip_validator.validate('/'))

        error = ValidationError(error_message="Invalid IP address value ''")
        self.assertEquals(error, self.vip_validator.validate(""))


class TestGateway6Validator(unittest.TestCase):
    def setUp(self):
        self.validator = Gateway6Validator()

    def test_route6_item_netmask_gateway(self):
        gateway = '2001::1/64'
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='Gateway address 2001::1/64 cannot have netmask.',
                    ),
                self.validator.validate(gateway)
            )

    @nottest
    def test_route6_item_malformed_gateway(self):
        bad_dest_route_props = {
                'subnet': '2eed:11:22:33::/64',
                'gateway': 'fxxx::1',
            }

        self._mock_root_and_node_types()
        self.model_manager.create_root_item('root', '/')
        route = self.model_manager.create_item(
                'route6',
                '/routes/def',
                **bad_dest_route_props
            )

        self.assertEquals(
                [ValidationError(
                        property_name='gateway',
                        error_message='Invalid IPv6Address value \'{0}\''.format(
                            bad_dest_route_props['gateway']
                            ),
                    )],
                route
            )

        # We shouldn't get a ValidationError from the Route item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEquals(
                None,
                self.route6_validator.validate(bad_dest_route_props)
            )

    def test_route6_item_mcast_gateway(self):
        gateway = 'ffff::1'
        # We shouldn't get a ValidationError from the Route item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='Cannot use multicast address '
                        'ffff::1 as gateway',
                    ),
                self.validator.validate(gateway)
            )

    def test_route6_item_netmask_gateway(self):
        gateway = '2001::1/64'
        self.assertEquals(
                ValidationError(
                    property_name='gateway',
                    error_message='Gateway address 2001::1/64 cannot have netmask.'
                    ),
                self.validator.validate(gateway)
            )

    def test_loopback_in_ipv6_gateway(self):
        gateway = '::1'
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address ::1 cannot be local loopback.'
                    ),
                self.validator.validate(gateway)
            )

    def test_undefined_in_ipv6_gateway(self):
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address :: cannot be the undefined address.'
                    ),
                self.validator.validate('::')
            )

    def test_link_local_in_ipv6_gateway(self):
        gateway = 'fe80::1'
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='The gateway address fe80::1 cannot be link-local.'
                    ),
                self.validator.validate(gateway)
            )

    def test_use_localhost_as_gateway_1(self):
        gateway = '::1'
        result = self.validator.validate(gateway)
        self.assertEquals(
            ValidationError(
                property_name='gateway',
        error_message='The gateway address ::1 cannot be local loopback.'
                ),
        result
            )

    def test_netmask_in_ipv6_gateway(self):
        gateway = '2001::1/16'
        self.assertEquals(
                ValidationError(
                        property_name='gateway',
                        error_message='Gateway address 2001::1/16 cannot have netmask.'
                    ),
                self.validator.validate(gateway)
            )

    def test_gateway_reserved(self):
        result = self.validator.validate('00b8::0')
        self.assertEqual(
            ValidationError(
                        property_name='gateway',
                        error_message='The gateway address 00b8::0 cannot be reserved.'),
            result
            )

    def test_empty_gateway(self):
        result = self.validator.validate('')
        self.assertEqual(
            ValidationError(
                        property_name='gateway',
                        error_message='Gateway cannot be empty.'),
            result
            )

    def test_n_zeros_group(self):
        result = self.validator.validate('2001:db8:::1')
        # We shouldn't get a ValidationError from the Gateway item's validator
        # when the gateway address is malformed because the property validator
        # should have caught that already
        self.assertEqual(None, result)


class TestSubnet6Validator(unittest.TestCase):
    def setUp(self):
        self.validator = Subnet6Validator()

    # IPv4 subnet disallowed..
    def test_subnet_ipv4(self):
        result = self.validator.validate("192.168.0.1/16")
        self.assertEqual(
            ValidationError(error_message="Invalid IPv6 subnet value "
                            "'192.168.0.1/16'"),
            result
            )

    def test_subnet_ipv6_exception(self):
        result = self.validator.validate(object())
        self.assertEqual(
            ValidationError(error_message="Invalid value: "
                            "unexpected type <type 'object'> for addr arg"),
            result
            )

    def test_subnet_no_prefix(self):
        expected = ValidationError(
                error_message='Subnet must include prefix length',
                )
        result = self.validator.validate("2dd3:2:3:4::")
        self.assertEqual(
                expected,
                result
            )

    def test_subnet_bad_prefix(self):
        address = '2002:2:3:4::0/129'
        expected = ValidationError(
                error_message="Invalid IPv6 subnet value '{0}'".format(address),
                )
        result = self.validator.validate(address)
        self.assertEqual(
                expected,
                result
            )

    def test_subnet_backslash(self):
        address = '2002::\\64'
        expected = ValidationError(
                error_message="Invalid IPv6 subnet value '{0}'".format(address),
                )
        result = self.validator.validate(address)
        self.assertEqual(
                expected,
                result
            )

    def test_subnet_mcast(self):
        expected = ValidationError(
                error_message="Subnet cannot be a multicast address.",
                )
        result = self.validator.validate("ff00::1/128")
        self.assertEqual(
                expected,
                result
            )

    def test_subnet_None(self):
        # Validation is aborted in this case
        result = self.validator.validate(None)
        self.assertEqual(
            None,
            result
            )

    def test_subnet_empty(self):
        result = self.validator.validate('')
        self.assertEqual(
            ValidationError(error_message='Subnet cannot be empty.'),
            result
            )

    def test_subnet_whitespace(self):
        result = self.validator.validate(' ')
        self.assertEqual(
            ValidationError(error_message='Invalid IPv6 subnet value \' \''),
            result
            )

    def test_subnet_reserved(self):
        result = self.validator.validate('::/128')
        self.assertEqual(
            ValidationError(error_message='Subnet cannot be a reserved network.'),
            result
            )

    def test_subnet_localhost(self):
        for mask in range(0,7):
            result = self.validator.validate('::1/{0}'.format(mask))
            self.assertEqual(
                ValidationError(error_message='Subnet cannot be loopback.'),
                result
            )
        for mask in range(8,128):
            result = self.validator.validate('::1/{0}'.format(mask))
            self.assertEqual(
                ValidationError(error_message='Subnet cannot be a reserved network.'.format(mask)),
                result
            )

    def test_subnet_linklocal(self):
        self.assertEquals(
            ValidationError(error_message='Cannot use link-local address fe80::/64 as subnet.'),
            self.validator.validate('fe80::/64')
            )

    def test_subnet_undefined(self):
        self.assertEquals(
            ValidationError(error_message='Subnet cannot be a reserved network.'),
            self.validator.validate('::/128')
            )

    def test_unallowed_0_prefix_for_not_default_gateway_ipv6_subnet(self):
        self.assertEquals(
            ValidationError(
                error_message="Routing destination '2001:db8::' cannot have prefix length 0, " \
                "because it is reserved for the default route only (::/0)."
                ),
            self.validator.validate('2001:db8::/0')
            )


class TestBondArpProperties(unittest.TestCase):
    def setUp(self):
        self.targets_validator = ArpIpTargetsValidator()
        self.arp_props_validator = ArpPropertiesValidator()

    def _create_n_ips_in_csl(self, num):
        ips = ['0.0.0.{0}'.format(i) for i in range(0, num)]
        return ','.join(ips)

    def test_invalid_arp_ip_target_address(self):
        for value in ("bogus",
                      "1.2.3,10.10.10.10"
                      "999.999.999", "999.999.999.999",
                      "1.2.3.4, ,9.8.7.6,",
                      "1.2.3.4,,9.8.7.6",
                      "10.44.86.999",
                      "10.44.86.888,10.44.86.999"):
            result = self.targets_validator.validate(value)
            msg = "Invalid IP address(es) in '%s'. " % value
            self.assertEqual(ValidationError(error_message=msg), result)

        value = self._create_n_ips_in_csl(17)
        result = self.targets_validator.validate(value)
        msg = "Too many IPv4 addresses in address list. "
        self.assertEqual(ValidationError(error_message=msg), result)

    def test_valid_arp_ip_target_address(self):
        value = self._create_n_ips_in_csl(16)
        result = self.targets_validator.validate(value)
        self.assertEqual(None, result)

        for value in ("1.2.3.4",
                      "1.2.3.4,9.8.7.6"):
            result = self.targets_validator.validate(value)
            self.assertEqual(None, result)

    def test_miimon_with_arp_properties(self):
        msg = 'Properties "arp_interval", "arp_ip_target", "arp_validate" ' \
              'and "arp_all_targets" are not allowed if "miimon" is specified.'

        expected = ValidationError(property_name='miimon',
                                   error_message=msg)

        for prop_list in [[('miimon', '100'),
                           ('arp_interval', '500')],
                          [('miimon', '100'),
                           ('arp_ip_target', '1.2.3.4')],
                          [('miimon', '100'),
                           ('arp_validate', 'active')],
                          [('miimon', '100'),
                           ('arp_all_targets', 'any')],
                          [('miimon', '100'),
                           ('arp_ip_target', '1.2.3.4'),
                           ('arp_validate', 'backup'),
                           ('arp_all_targets', 'any'),
                           ('arp_interval', '500')]]:
            properties = {'mode': '1'}
            for (name, value)in prop_list:
                properties[name] = value
            result = self.arp_props_validator.validate(properties)
            self.assertEqual(expected, result)

        # ----

        msg = 'Properties "arp_interval" and "arp_ip_target" ' \
              'must both be specified.'

        for (name, value) in [('arp_interval', '100'),
                              ('arp_ip_target', '1.2.3.4')]:
            properties = {'mode': '1'}
            properties[name] = value

            expected = ValidationError(property_name=name,
                                       error_message=msg)

            result = self.arp_props_validator.validate(properties)
            self.assertEqual(expected, result)

        # ---

        for (name, value) in [('arp_validate', 'active'),
                              ('arp_all_targets', 'any')]:
            properties = {'mode': '1',
                          name: value}
            msg = 'Properties "arp_interval" and "arp_ip_target" must be specified when using "%s"' % name

            expected = ValidationError(property_name=name,
                                       error_message=msg)

            result = self.arp_props_validator.validate(properties)
            self.assertEqual(expected, result)

        # ----

        msg = 'Properties "arp_validate" and "arp_all_targets" must both be specified.'

        for (name, value) in [('arp_validate', 'active'),
                              ('arp_all_targets', 'any')]:
            properties = {'mode': '1',
                          'arp_interval': '500',
                          'arp_ip_target': '1.2.3.4',
                          name: value}

            expected = ValidationError(property_name=name,
                                       error_message=msg)

            result = self.arp_props_validator.validate(properties)
            self.assertEqual(expected, result)

        # ----

        for mode in ['0', '1', '2', '3', 'balance-rr', 'active-backup', 'balance-xor', 'broadcast']:
            properties = {'mode': mode,
                          'arp_interval': '500',
                          'arp_ip_target': '1.2.3.4'}
            result = self.arp_props_validator.validate(properties)
            self.assertEqual(None, result)

        # ----

        for mode in ['4', '5', '6', '802.3ad', 'balance-tlb', 'balance-alb']:
            properties = {'mode': mode,
                          'arp_interval': '500',
                          'arp_ip_target': '1.2.3.4'}
            result = self.arp_props_validator.validate(properties)

            msg = 'ARP monitoring is only supported with "mode" property ' \
                  'set to one of the following: "0", "balance-rr", ' \
                  '"1", "active-backup", ' \
                  '"2", "balance-xor", "3", "broadcast"'

            expected = ValidationError(property_name='mode',
                                       error_message=msg)
            self.assertEqual(expected, result)

        # ----

        for mode in ['1', 'active-backup']:
            properties = {'mode': mode,
                          'arp_ip_target': '1.2.3.4',
                          'arp_validate': 'backup',
                          'arp_all_targets': 'any',
                          'arp_interval': '500'}
            result = self.arp_props_validator.validate(properties)
            self.assertEqual(None, result)

        # ----

        msg = '"arp_validate" is only supported with "mode" property set to "1" or "active-backup"'
        expected = ValidationError(property_name='mode',
                                   error_message=msg)
        for mode in ['0', '2', '3', '4', '5', '6',
                     'balance-rr', 'balance-xor', 'broadcast', '802.3ad', 'balance-tlb', 'balance-alb']:
            properties = {'mode': mode,
                          'arp_ip_target': '9.8.7.6',
                          'arp_validate': 'all',
                          'arp_all_targets': 'all',
                          'arp_interval': '500'}
            result = self.arp_props_validator.validate(properties)
            self.assertEqual(expected, result)


class TestForHashMax(unittest.TestCase):
    def setUp(self):
        self.vld8rs = NetworkExtension.create_hash_max_vld8rs()

        self.power2_validator = self.vld8rs[1]
        self.range_validator = self.vld8rs[2]

    def test_power2_validator(self):
        def gen(x):
            i = 2
            for n in range(x + 2):
                yield i
                i <<= 1

        # ----

        numbers = list(gen(20))

        for power2 in numbers:
            self.assertEquals(None, self.power2_validator.validate("%d" % power2))

        # ----

        for power2 in numbers:
            non_power2 = power2 + 1
            msg = 'Property value "%d" is not a power of two between 1 and %d' % \
                  (non_power2, NetworkExtension.MULTICAST_HASH_SIZE_MAX)
            expected = ValidationError(error_message=msg,
                                       property_name='hash_max')
            self.assertEquals(expected, self.power2_validator.validate("%d" % non_power2))


    def test_range_validator(self):

        just_right = NetworkExtension.MULTICAST_HASH_SIZE_MAX - 1
        self.assertEquals(None, self.range_validator.validate("%d" % just_right))

        # ----

        msg = "Value outside range 1 - %d" % NetworkExtension.MULTICAST_HASH_SIZE_MAX
        expected = ValidationError(error_message=msg)
        too_big = NetworkExtension.MULTICAST_HASH_SIZE_MAX + 1
        self.assertEquals(expected, self.range_validator.validate("%d" % too_big))


class TestPxeBootOnlyValidator(unittest.TestCase):
    def setUp(self):
        self.validator = PxeBootOnlyValidator()
        self._devname = 'ethx'
        self._error = ('Properties "ipaddress"/"ipv6address", '
                       '"network_name", "bridge" and "bond" are not '
                       'allowed when "pxe_boot_only" property is set to "true"')

    def _assert_error_property_not_allowed(self, prop, value):
        props = {'pxe_boot_only': 'true', 'device_name': self._devname,
                prop: value}
        self.assertEquals(ValidationError(
                property_name='pxe_boot_only',
                error_message=self._error),
                self.validator.validate(props))

    def test_ipaddress_set(self):
        self._assert_error_property_not_allowed('ipaddress', '192.168.0.1')

    def test_ip6address_set(self):
        self._assert_error_property_not_allowed('ipv6address', '192.168.0.1')

    def test_network_name_set(self):
        self._assert_error_property_not_allowed('network_name', 'net_name')

    def test_bridge_set(self):
        self._assert_error_property_not_allowed('bridge', 'br0')

    def test_bond_set(self):
        self._assert_error_property_not_allowed('master', 'bond0')

    def test_device_name_set(self):
        props = {'pxe_boot_only': 'true', 'device_name': self._devname}
        self.assertEqual(None, self.validator.validate(props))

    def test_mac_set(self):
        props = {'pxe_boot_only': 'true', 'device_name': self._devname,
                 'macaddress': 'AA:BB'}
        self.assertEqual(None, self.validator.validate(props))
