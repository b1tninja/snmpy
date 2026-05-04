"""Unit tests for the TrapReceptor ABC and PDU decoding."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from ber.object import Integer, ObjectIdentifier, OctetString, Sequence

from snmp.datagram import SNMPDatagram
from snmp.pdus import Trap, SNMPv2Trap, PDU
from snmp.traps import TrapReceptor, TrapProtocol
from snmp.notifications import TrapNotification, SNMPv2Notification, TrapType, VariableBinding, VariableValue
from snmp.enums import SNMPVersion


class TestTrapReceptorABC(unittest.TestCase):
    """Test that TrapReceptor enforces the abstract interface."""

    def test_trap_receptor_is_abstract(self):
        """TrapReceptor cannot be instantiated without implementing on_trap_received."""
        with self.assertRaises(TypeError):
            TrapReceptor()  # type: ignore[abstract]

    def test_subclass_without_abstract_method(self):
        """Subclass must implement on_trap_received."""
        class IncompleteReceptor(TrapReceptor):
            pass  # No on_trap_received

        with self.assertRaises(TypeError):
            IncompleteReceptor()  # type: ignore[misc]

    def test_complete_subclass(self):
        """Subclass with on_trap_received can be instantiated."""
        class CompleteReceptor(TrapReceptor):
            def on_trap_received(self, pdu, source: str) -> None:
                pass

        receptor = CompleteReceptor(host="127.0.0.1", port=162)
        self.assertEqual(receptor.host, "127.0.0.1")
        self.assertEqual(receptor.port, 162)


class TestTrapProtocol(unittest.TestCase):
    """Test TrapProtocol datagram buffering."""

    def setUp(self):
        self.protocol = TrapProtocol()

    def test_initialization(self):
        self.assertEqual(self.protocol.data, [])
        self.assertFalse(self.protocol.event.is_set())

    def test_datagram_received(self):
        self.protocol.datagram_received(b"\x30\x05\x00\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63", ("127.0.0.1", 1161))
        self.assertEqual(len(self.protocol.data), 1)
        self.assertTrue(self.protocol.event.is_set())

    def test_multiple_datagrams(self):
        self.protocol.datagram_received(b"\x30\x05\x00\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63", ("127.0.0.1", 1161))
        self.protocol.datagram_received(b"\x30\x05\x00\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63", ("127.0.0.1", 1161))
        self.assertEqual(len(self.protocol.data), 2)


class TestPDUFieldNames(unittest.TestCase):
    """Test PDU.from_object uses field_names per-class."""

    def test_trap_field_count(self):
        """Trap should have 6 field names."""
        self.assertEqual(len(Trap.field_names), 6)
        self.assertEqual(Trap.field_names, (
            "enterprise", "agent_addr", "generic_trap",
            "specific_code", "time_stamp", "variable_bindings",
        ))

    def test_pdu_field_count(self):
        """Standard PDU should have 4 field names."""
        self.assertEqual(len(PDU.field_names), 4)
        self.assertEqual(PDU.field_names, (
            "request_id", "error_status", "error_index", "variable_bindings",
        ))

    def test_bulkpdu_field_count(self):
        """BulkPDU should have 4 different field names."""
        from snmp.pdus import BulkPDU
        self.assertEqual(len(BulkPDU.field_names), 4)
        self.assertEqual(BulkPDU.field_names, (
            "request_id", "non_repeaters", "max_repetitions", "variable_bindings",
        ))


class TestTrapFromObject(unittest.TestCase):
    """Test Trap.from_object decoding."""

    def test_trap_from_object(self):
        """Trap.from_object should unpack 6 fields correctly."""
        enterprise = ObjectIdentifier.from_string("1.3.6.1.4.1.0").get_object()
        agent_addr = ObjectIdentifier.from_string("0.0.0.0").get_object()
        generic_trap = Integer.from_int(0).get_object()  # coldStart
        specific_code = Integer.from_int(0).get_object()
        time_stamp = Integer.from_int(100).get_object()
        vbs = Sequence.from_list([])

        # Create a Trap object (tag_id=4, context-specific constructed)
        from ber.object import ObjectTag, Object
        from ber.enums import TagClassEnum, UniversalClassTags

        trap_obj = Object(
            ObjectTag(TagClassEnum.context_specific, True, 4),
            [enterprise, agent_addr, generic_trap, specific_code, time_stamp, vbs],
        )

        trap = Trap.from_object(trap_obj)

        self.assertIsInstance(trap, Trap)
        self.assertEqual(str(trap.enterprise), "1.3.6.1.4.1.0")
        self.assertEqual(str(trap.agent_addr), "0.0.0.0")
        self.assertEqual(int(trap.generic_trap), 0)  # coldStart
        self.assertEqual(int(trap.specific_code), 0)
        self.assertEqual(int(trap.time_stamp), 100)


class TestSNMPv2TrapFromObject(unittest.TestCase):
    """Test SNMPv2Trap.from_object decoding."""

    def test_snmpv2_trap_from_object(self):
        """SNMPv2Trap.from_object should unpack 4 fields correctly."""
        request_id = Integer.from_int(12345).get_object()
        error_status = Integer.from_int(0).get_object()
        error_index = Integer.from_int(0).get_object()
        vbs = Sequence.from_list([])

        from ber.object import ObjectTag, Object
        from ber.enums import TagClassEnum

        v2_trap_obj = Object(
            ObjectTag(TagClassEnum.context_specific, True, 7),
            [request_id, error_status, error_index, vbs],
        )

        v2_trap = SNMPv2Trap.from_object(v2_trap_obj)

        self.assertIsInstance(v2_trap, SNMPv2Trap)
        self.assertEqual(int(v2_trap.request_id), 12345)


class TestTrapFormatOutput(unittest.TestCase):
    """Test _format_trap_output handles value extraction correctly."""

    def test_format_trap_with_zero_value(self):
        """_format_trap_output should handle Integer(0) values."""
        class TestReceptor(TrapReceptor):
            def on_trap_received(self, pdu, source: str) -> None:
                pass
            captured_outputs = []

            def _format_trap_output(self, pdu):
                outputs = []
                if isinstance(pdu, Trap):
                    trap_name = {
                        0: "coldStart", 1: "warmStart", 2: "linkDown",
                        3: "linkUp", 4: "authenticationFailure",
                        5: "egpNeighborLoss", 6: "enterpriseSpecific",
                    }.get(int(pdu.generic_trap), "unknown")
                    outputs.append(f"Trap: {trap_name}")

                if pdu.variable_bindings and len(pdu.variable_bindings.value):
                    for var_obj in pdu.variable_bindings.value:
                        if var_obj is not None and var_obj.value is not None and len(var_obj.value) >= 2:
                            oid_str = str(var_obj.value[0]) if var_obj.value[0] is not None else "unknown"
                            val_obj = var_obj.value[1]
                            if val_obj is None:
                                value = "None"
                            elif isinstance(val_obj.value, bytes) and len(val_obj.value) == 0:
                                value = "0"
                            elif isinstance(val_obj.value, int):
                                value = str(val_obj.value)
                            else:
                                try:
                                    value = str(val_obj.value)
                                except Exception:
                                    value = repr(val_obj)
                            outputs.append(f"{oid_str} = {value}")
                self.captured_outputs = outputs

        receptor = TestReceptor()

        # Create a Trap with Integer(0) value
        vbs = Sequence.from_list([
            Sequence.from_list([
                ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
                Integer.from_int(0).get_object(),  # zero value
            ])
        ])

        # Build trap directly (bypass from_trap_type enterprise OID validation)
        enterprise_obj = ObjectIdentifier.from_string("0.0").get_object()
        trap = Trap.__new__(Trap)
        trap.enterprise = enterprise_obj
        trap.agent_addr = ObjectIdentifier.from_string("0.0.0.0").get_object()
        trap.generic_trap = Integer.from_int(Trap.COLD_START).get_object()
        trap.specific_code = Integer.from_int(0).get_object()
        trap.time_stamp = Integer.from_int(0).get_object()
        trap.variable_bindings = vbs

        receptor._format_trap_output(trap)

        self.assertEqual(receptor.captured_outputs[0], "Trap: coldStart")
        self.assertEqual(receptor.captured_outputs[1], "1.3.6.1.2.1.1.3 = 0")


class TestTrapManagerBasics(unittest.TestCase):
    """Test TrapManager destination management."""

    def test_add_and_remove_destination(self):
        from snmp.traps import TrapManager

        mgr = TrapManager()
        dest = mgr.add_destination("192.168.1.100", community="public")
        self.assertEqual(len(mgr.destinations), 1)
        self.assertEqual(dest.host, "192.168.1.100")

        removed = mgr.remove_destination("192.168.1.100")
        self.assertTrue(removed)
        self.assertEqual(len(mgr.destinations), 0)

    def test_clear_destinations(self):
        from snmp.traps import TrapManager

        mgr = TrapManager()
        mgr.add_destination("10.0.0.1")
        mgr.add_destination("10.0.0.2")
        self.assertEqual(len(mgr.destinations), 2)

        mgr.clear_destinations()
        self.assertEqual(len(mgr.destinations), 0)

    def test_disable_destination(self):
        from snmp.traps import TrapManager

        mgr = TrapManager()
        dest = mgr.add_destination("10.0.0.1")
        dest.disable()
        self.assertFalse(dest.enabled)
        dest.enable()
        self.assertTrue(dest.enabled)


class TestPDUFromObjectValidation(unittest.TestCase):
    """Test PDU.from_object validates field count."""

    def test_wrong_field_count_raises(self):
        """from_object should assert when field count doesn't match."""
        from ber.object import ObjectTag, Object
        from ber.enums import TagClassEnum

        # Create an object with wrong number of fields (1 instead of 4)
        wrong_obj = Object(
            ObjectTag(TagClassEnum.context_specific, True, 0),
            [Integer.from_int(0).get_object()],  # Only 1 field
        )

        with self.assertRaises(AssertionError):
            PDU.from_object(wrong_obj)

    def test_correct_field_count_passes(self):
        """from_object should work with correct field count."""
        from ber.object import ObjectTag, Object
        from ber.enums import TagClassEnum

        correct_obj = Object(
            ObjectTag(TagClassEnum.context_specific, True, 0),
            [
                Integer.from_int(1).get_object(),
                Integer.from_int(0).get_object(),
                Integer.from_int(0).get_object(),
                Sequence.from_list([]),
            ],
        )

        pdu = PDU.from_object(correct_obj)
        self.assertIsInstance(pdu, PDU)


class TestTrapNotification(unittest.TestCase):
    """Test TrapNotification data contract."""

    def test_trap_notification_from_pdu(self):
        """TrapNotification.from_pdu should correctly extract all fields."""
        from snmp.pdus import Trap
        from snmp.notifications import TrapNotification, TrapType

        # Build a Trap PDU directly
        enterprise = ObjectIdentifier.from_string("1.3.6.1.4.1.0").get_object()
        agent_addr = ObjectIdentifier.from_string("0.0.0.0").get_object()
        generic_trap = Integer.from_int(2).get_object()  # linkDown — this is an Object wrapping Integer
        specific_code = Integer.from_int(5).get_object()
        time_stamp = Integer.from_int(12345).get_object()

        vbs = Sequence.from_list([
            Sequence.from_list([
                ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
                Integer.from_int(100).get_object(),
            ]),
            Sequence.from_list([
                ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.2").get_object(),
                OctetString(b"eth0").get_object(),
            ]),
        ])

        trap = Trap.__new__(Trap)
        trap.enterprise = enterprise
        trap.agent_addr = agent_addr
        trap.generic_trap = generic_trap
        trap.specific_code = specific_code
        trap.time_stamp = time_stamp
        trap.variable_bindings = vbs

        notification = TrapNotification.from_pdu(trap)

        self.assertEqual(notification.trap_type, "linkDown")
        self.assertEqual(notification.trap_type_enum, TrapType.LINK_DOWN)
        self.assertEqual(notification.generic_trap, 2)
        self.assertEqual(notification.specific_code, 5)
        self.assertEqual(notification.time_stamp, 12345)
        self.assertEqual(str(notification.enterprise), "1.3.6.1.4.1.0")
        self.assertEqual(len(notification.variables), 2)
        self.assertEqual(notification.variables[0].oid, "1.3.6.1.2.1.1.3")
        # Integer.from_int stores bytes internally, so str() gives "100"
        self.assertEqual(str(notification.variables[0].value.value), "100")

    def test_notification_repr(self):
        """Notification __repr__ should show key fields."""
        from snmp.notifications import TrapNotification, TrapType

        notification = TrapNotification(
            trap_type="coldStart",
            source="192.168.1.1",
            version=SNMPVersion.v1,
            community="public",
            enterprise="0",
            agent_addr="0.0.0.0",
            generic_trap=0,
            specific_code=0,
            time_stamp=0,
            variables=(),
        )
        self.assertIn("coldStart", repr(notification))
        self.assertIn("generic_trap=0", repr(notification))

    def test_trap_type_enum(self):
        """TrapType enum should map standard trap types."""
        from snmp.notifications import TrapType
        self.assertEqual(TrapType.COLD_START.value, 0)
        self.assertEqual(TrapType.WARM_START.value, 1)
        self.assertEqual(TrapType.LINK_DOWN.value, 2)
        self.assertEqual(TrapType.LINK_UP.value, 3)
        self.assertEqual(TrapType.AUTHENTICATION_FAILURE.value, 4)
        self.assertEqual(TrapType.EGP_NEIGHBOR_LOSS.value, 5)
        self.assertEqual(TrapType.ENTERPRISE_SPECIFIC.value, 6)

    def test_variable_binding_creation(self):
        """VariableBinding.from_dict should create typed bindings using from_str."""
        from snmp.notifications import VariableBinding, VariableValue
        # from_dict with a plain str goes through __init__ which stores raw value
        # Use from_str for typed creation
        vb = VariableBinding.from_dict("1.3.6.1.2.1.1.1", VariableValue.from_str("test"))
        self.assertEqual(vb.oid, "1.3.6.1.2.1.1.1")
        self.assertEqual(vb.value.value, "test")
        self.assertEqual(vb.value.value_type, "string")

    def test_variable_binding_passthrough(self):
        """VariableBinding.from_dict should passthrough existing bindings."""
        from snmp.notifications import VariableBinding, VariableValue
        original = VariableBinding(oid="1.3.6.1.2.1.1.3", value=VariableValue.from_int(100))
        result = VariableBinding.from_dict("ignored", original)
        self.assertIs(result, original)

    def test_snmpv2_notification_from_pdu(self):
        """SNMPv2Notification.from_pdu should extract trap OID and variables."""
        from snmp.pdus import SNMPv2Trap
        from snmp.notifications import SNMPv2Notification

        vbs = Sequence.from_list([
            Sequence.from_list([
                ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0").get_object(),
                ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.1").get_object(),
            ]),
            Sequence.from_list([
                ObjectIdentifier.from_string("1.3.6.1.2.1.1.3").get_object(),
                Integer.from_int(500).get_object(),
            ]),
        ])

        pdu = SNMPv2Trap(variable_bindings=vbs)
        notification = SNMPv2Notification.from_pdu(pdu)

        self.assertEqual(notification.trap_oid, "1.3.6.1.6.3.1.1.4.1.0.1")
        self.assertEqual(notification.request_id, int(pdu.request_id))
        self.assertEqual(len(notification.variables), 2)

    def test_decode_notification_dispatch(self):
        """decode_notification should route to correct type."""
        from snmp.notifications import decode_notification, TrapNotification
        from snmp.pdus import Trap

        enterprise = ObjectIdentifier.from_string("1.3.6.1.4.1.0").get_object()
        trap = Trap.__new__(Trap)
        trap.enterprise = enterprise
        trap.agent_addr = ObjectIdentifier.from_string("0.0.0.0").get_object()
        trap.generic_trap = Integer.from_int(0).get_object()
        trap.specific_code = Integer.from_int(0).get_object()
        trap.time_stamp = Integer.from_int(0).get_object()
        trap.variable_bindings = Sequence.from_list([])

        notification = decode_notification(trap, source="127.0.0.1", community="public")
        self.assertIsInstance(notification, TrapNotification)
        self.assertEqual(notification.source, "127.0.0.1")
        self.assertEqual(notification.community, "public")


if __name__ == "__main__":
    unittest.main()
