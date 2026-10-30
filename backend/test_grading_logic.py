import tempfile
import unittest
from pathlib import Path

import yaml

from grading_engine import grade_lab
from simulator import SimulationManager


BACKEND_DIR = Path(__file__).resolve().parent
LABS_DIR = BACKEND_DIR.parent / "labs"


class NativeGradingTests(unittest.TestCase):
    def setUp(self):
        self.manager = SimulationManager()
        self.addCleanup(self.manager.clear)

    def runtime(self, slug):
        return self.manager.create(
            slug=slug, yaml_path=str(LABS_DIR / slug / "lab.yaml")
        )

    def solution(self, slug, node):
        return (LABS_DIR / slug / f"solution_{node}.cfg").read_text(encoding="utf-8")

    def test_grading_rejects_missing_configuration_and_reports_lines(self):
        runtime = self.runtime("ssh-hardening")
        report = grade_lab(
            str(LABS_DIR / "ssh-hardening" / "lab.yaml"),
            snapshot=runtime.snapshot(),
        )
        self.assertFalse(report["passed"])
        self.assertEqual(report["percentage"], 0)
        r1 = next(item for item in report["node_results"] if item["node"] == "R1")
        self.assertIn("enable secret Cisco123!", r1["missing_lines"])
        self.assertIn("banner motd Authorized Access Only", r1["missing_lines"])
        pc1 = next(item for item in report["node_results"] if item["node"] == "PC1")
        self.assertFalse(pc1["passed"])
        self.assertIn("Skipping", pc1["error"])
        self.assertIn("Behavioral verification failed", pc1["error"])

    def test_password_and_banner_values_are_meaningful(self):
        runtime = self.runtime("ssh-hardening")
        wrong = self.solution("ssh-hardening", "R1")
        wrong = wrong.replace("Cisco123!", "WrongSecret").replace(
            "Authorized Access Only", "Wrong Banner"
        )
        runtime.apply_config(
            "R1",
            wrong
            + "\ninterface Ethernet0/0\n no shutdown\n"
            + "crypto key generate rsa modulus 2048\n",
        )
        report = grade_lab(
            str(LABS_DIR / "ssh-hardening" / "lab.yaml"),
            snapshot=runtime.snapshot(),
        )
        r1 = next(item for item in report["node_results"] if item["node"] == "R1")
        self.assertIn("enable secret Cisco123!", r1["missing_lines"])
        self.assertIn("banner motd Authorized Access Only", r1["missing_lines"])
        self.assertIn("username admin secret Cisco123!", r1["missing_lines"])

    def test_complete_ospf_configuration_passes_with_full_adjacency(self):
        runtime = self.runtime("ospf-basic")
        runtime.apply_config(
            "R1",
            "interface e0/0\n ip address 192.168.1.1 255.255.255.0\n"
            " no shutdown\nrouter ospf 1\n network 192.168.1.0 0.0.0.255 area 0",
        )
        runtime.apply_config(
            "R2",
            "interface e0/1\n ip address 192.168.1.2 255.255.255.0\n"
            " no shutdown\nrouter ospf 1\n network 192.168.1.0 0.0.0.255 area 0",
        )
        report = grade_lab(
            str(LABS_DIR / "ospf-basic" / "lab.yaml"),
            snapshot=runtime.snapshot(),
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["total_earned"], 100)

    def test_successful_pings_do_not_override_missing_required_config(self):
        runtime = self.runtime("roas-1")
        runtime.apply_config("SW1", self.solution("roas-1", "SW1"))
        runtime.apply_config(
            "R1",
            "interface e0/0\n no shutdown\n"
            "interface e0/0.10\n encapsulation dot1q 10\n"
            " ip address 192.168.10.1 255.255.255.0\n"
            "interface e0/0.20\n encapsulation dot1q 20\n"
            " ip address 192.168.20.1 255.255.255.0\n"
            "ip dhcp pool WRONG10\n network 192.168.10.0 255.255.255.0\n"
            " default-router 192.168.10.1\n"
            "ip dhcp pool WRONG20\n network 192.168.20.0 255.255.255.0\n"
            " default-router 192.168.20.1",
        )
        for node in ("PC1", "PC2"):
            terminal = self.manager.attach(runtime.runtime_id, node)
            self.manager.execute(terminal, "ip dhcp\r")
        self.assertTrue(runtime.network().can_reach("PC1", "192.168.10.1"))
        self.assertTrue(runtime.network().can_reach("PC2", "192.168.20.1"))

        report = grade_lab(
            str(LABS_DIR / "roas-1" / "lab.yaml"),
            snapshot=runtime.snapshot(),
        )
        self.assertFalse(report["passed"])
        r1 = next(item for item in report["node_results"] if item["node"] == "R1")
        self.assertTrue(any("ip dhcp pool VLAN10" in line for line in r1["missing_lines"]))

    def test_all_current_labs_can_reach_a_passing_state(self):
        reports = {}

        etherchannel = self.runtime("etherchannel-lacp")
        for node in ("S1", "S2"):
            etherchannel.apply_config(
                node, self.solution("etherchannel-lacp", node)
            )
        reports["etherchannel-lacp"] = grade_lab(
            str(LABS_DIR / "etherchannel-lacp" / "lab.yaml"),
            snapshot=etherchannel.snapshot(),
        )

        ntp = self.runtime("ntp-fundamentals")
        for node in ("R0", "R1", "R2", "R3"):
            ntp.apply_config(node, self.solution("ntp-fundamentals", node))
        reports["ntp-fundamentals"] = grade_lab(
            str(LABS_DIR / "ntp-fundamentals" / "lab.yaml"),
            snapshot=ntp.snapshot(),
        )

        ospf = self.runtime("ospf-basic")
        ospf.apply_config(
            "R1",
            "interface e0/0\n ip address 192.168.1.1 255.255.255.0\n"
            " no shutdown\nrouter ospf 1\n network 192.168.1.0 0.0.0.255 area 0",
        )
        ospf.apply_config(
            "R2",
            "interface e0/1\n ip address 192.168.1.2 255.255.255.0\n"
            " no shutdown\nrouter ospf 1\n network 192.168.1.0 0.0.0.255 area 0",
        )
        reports["ospf-basic"] = grade_lab(
            str(LABS_DIR / "ospf-basic" / "lab.yaml"),
            snapshot=ospf.snapshot(),
        )

        roas1 = self.runtime("roas-1")
        roas1.apply_config("SW1", self.solution("roas-1", "SW1"))
        roas1.apply_config(
            "R1",
            "interface e0/0\n no shutdown\n"
            + self.solution("roas-1", "R1"),
        )
        for node in ("PC1", "PC2"):
            terminal = self.manager.attach(roas1.runtime_id, node)
            self.manager.execute(terminal, "ip dhcp\r")
        reports["roas-1"] = grade_lab(
            str(LABS_DIR / "roas-1" / "lab.yaml"),
            snapshot=roas1.snapshot(),
        )

        roas2 = self.runtime("roas-2")
        for node in ("S1", "S2"):
            roas2.apply_config(node, self.solution("roas-2", node))
        roas2.apply_config(
            "R1",
            "interface e0/0\n no shutdown\n"
            + self.solution("roas-2", "R1"),
        )
        for node in ("PC0", "PC1", "PC2", "PC3"):
            terminal = self.manager.attach(roas2.runtime_id, node)
            self.manager.execute(terminal, "ip dhcp\r")
        reports["roas-2"] = grade_lab(
            str(LABS_DIR / "roas-2" / "lab.yaml"),
            snapshot=roas2.snapshot(),
        )

        ssh = self.runtime("ssh-hardening")
        ssh.apply_config(
            "R1",
            self.solution("ssh-hardening", "R1")
            + "\ninterface e0/0\n no shutdown\n"
            + "crypto key generate rsa modulus 2048\n",
        )
        ssh.apply_config(
            "SW1",
            self.solution("ssh-hardening", "SW1")
            + "\ninterface vlan1\n no shutdown\n",
        )
        reports["ssh-hardening"] = grade_lab(
            str(LABS_DIR / "ssh-hardening" / "lab.yaml"),
            snapshot=ssh.snapshot(),
        )

        for slug, report in reports.items():
            with self.subTest(lab=slug):
                self.assertTrue(
                    report["passed"],
                    msg=f"{slug}: {report['node_results']}",
                )

    def test_missing_solution_only_skips_hosts(self):
        definition = {
            "lab": {
                "id": "missing-router-solution",
                "title": "Missing router solution",
                "nodes": [{"name": "R1", "device_type": "cisco_ios_telnet"}],
                "links": [],
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            yaml_path = Path(directory) / "lab.yaml"
            yaml_path.write_text(yaml.safe_dump(definition), encoding="utf-8")
            runtime = self.manager.create(
                slug="missing-router-solution", yaml_path=str(yaml_path)
            )
            report = grade_lab(str(yaml_path), snapshot=runtime.snapshot())
        self.assertFalse(report["passed"])
        self.assertIn("Required solution file", report["node_results"][0]["missing_lines"][0])

    def _inline_runtime(
        self, directory, slug, nodes, links=None, checks=None, solutions=None
    ):
        definition = {
            "lab": {
                "id": slug,
                "title": slug,
                "nodes": nodes,
                "links": links or [],
            }
        }
        if checks is not None:
            definition["lab"]["checks"] = checks
        yaml_path = Path(directory) / "lab.yaml"
        yaml_path.write_text(yaml.safe_dump(definition), encoding="utf-8")
        for node_name, config in (solutions or {}).items():
            (Path(directory) / f"solution_{node_name}.cfg").write_text(
                config, encoding="utf-8"
            )
        runtime = self.manager.create(slug=slug, yaml_path=str(yaml_path))
        return runtime, yaml_path

    def test_slash_zero_dhcp_allocation_is_lazy_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._inline_runtime(
                directory,
                "dhcp-slash-zero",
                [
                    {"name": "R1", "kind": "router", "cli_profile": "ios"},
                    {"name": "PC1", "kind": "host", "cli_profile": "vpcs"},
                ],
                [["R1", "Ethernet0/0", "PC1", "Ethernet0/0"]],
            )
            runtime.apply_config(
                "R1",
                "interface Ethernet0/0\n"
                " ip address 0.0.0.1 0.0.0.0\n"
                " no shutdown\n"
                "ip dhcp pool BROAD\n"
                " network 0.0.0.0 0.0.0.0\n"
                " default-router 0.0.0.1",
            )
            terminal = self.manager.attach(runtime.runtime_id, "PC1")
            output = self.manager.execute(terminal, "ip dhcp\r")
            interface = runtime.nodes["PC1"].first_host_interface()

        self.assertEqual(interface.ip_address, "0.0.0.10")
        self.assertEqual(interface.address_source, "dhcp")
        self.assertIn("DDORA IP 0.0.0.10/0.0.0.0", output)
        self.assertEqual(runtime.network().DHCP_CANDIDATE_PROBE_LIMIT, 4096)

    def test_console_enable_and_ssh_passwords_are_exact_and_not_echoed(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._inline_runtime(
                directory,
                "interactive-auth",
                [{"name": "R1", "kind": "router", "cli_profile": "ios"}],
            )
            runtime.apply_config(
                "R1",
                "enable secret EnableSecret!\n"
                "service password-encryption\n"
                "username admin secret UserSecret!\n"
                "line con 0\n"
                " password ConsoleSecret!\n"
                " login",
            )
            terminal = self.manager.attach(runtime.runtime_id, "R1")
            self.assertIn("Password: ", terminal.initial_output)
            self.assertNotIn("R1>", terminal.initial_output)

            wrong_console = self.manager.execute(terminal, "WrongConsole\r")
            self.assertNotIn("WrongConsole", wrong_console)
            self.assertIn("% Login invalid", wrong_console)
            correct_console = self.manager.execute(terminal, "ConsoleSecret!\r")
            self.assertNotIn("ConsoleSecret!", correct_console)
            self.assertIn("R1>", correct_console)

            enable_prompt = self.manager.execute(terminal, "enable\r")
            self.assertIn("Password: ", enable_prompt)
            wrong_enable = self.manager.execute(terminal, "enablesecret!\r")
            self.assertNotIn("enablesecret!", wrong_enable)
            self.assertIn("% Access denied", wrong_enable)
            self.manager.execute(terminal, "enable\r")
            correct_enable = self.manager.execute(terminal, "EnableSecret!\r")
            self.assertNotIn("EnableSecret!", correct_enable)
            self.assertIn("R1#", correct_enable)

            shown = self.manager.execute(terminal, "show running-config\r")

        for secret in ("EnableSecret!", "UserSecret!", "ConsoleSecret!"):
            self.assertNotIn(secret, shown)
        self.assertRegex(shown, r"enable secret 5 \$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}")
        self.assertRegex(
            shown, r"username admin secret 5 \$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}"
        )
        self.assertRegex(shown, r"password 7 [0-9A-Fa-f]+")

    def test_ssh_prompts_and_rejects_wrong_secret_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._inline_runtime(
                directory,
                "ssh-exact-secret",
                [
                    {"name": "PC1", "kind": "host", "cli_profile": "ios"},
                    {"name": "R1", "kind": "router", "cli_profile": "ios"},
                ],
                [["PC1", "Ethernet0/0", "R1", "Ethernet0/0"]],
            )
            runtime.apply_config(
                "PC1",
                "interface Ethernet0/0\n"
                " ip address 10.0.0.2 255.255.255.0\n"
                " no shutdown",
            )
            runtime.apply_config(
                "R1",
                "interface Ethernet0/0\n"
                " ip address 10.0.0.1 255.255.255.0\n"
                " no shutdown\n"
                "ip domain-name example.test\n"
                "username admin secret ExactUserSecret!\n"
                "ip ssh version 2\n"
                "crypto key generate rsa modulus 2048\n"
                "line vty 0 4\n"
                " login local\n"
                " transport input ssh",
            )
            terminal = self.manager.attach(runtime.runtime_id, "PC1")
            prompt = self.manager.execute(
                terminal, "ssh -l admin 10.0.0.1\r"
            )
            self.assertIn("Password: ", prompt)
            self.assertNotIn("authentication accepted", prompt.lower())

            rejected = self.manager.execute(terminal, "WrongUserSecret!\r")
            self.assertNotIn("WrongUserSecret!", rejected)
            self.assertIn("Authentication failed", rejected)
            self.manager.execute(terminal, "ssh -l admin 10.0.0.1\r")
            accepted = self.manager.execute(terminal, "ExactUserSecret!\r")

        self.assertNotIn("ExactUserSecret!", accepted)
        self.assertIn("Password authentication accepted", accepted)

    def test_ssh_operational_grading_requires_exactly_2048_bit_rsa(self):
        runtime = self.runtime("ssh-hardening")
        runtime.apply_config(
            "R1",
            self.solution("ssh-hardening", "R1")
            + "\ncrypto key generate rsa modulus 512\n",
        )
        report = grade_lab(
            str(LABS_DIR / "ssh-hardening" / "lab.yaml"),
            snapshot=runtime.snapshot(),
        )
        r1 = next(item for item in report["node_results"] if item["node"] == "R1")
        self.assertFalse(r1["passed"])
        self.assertTrue(
            any("exactly 2048 bits" in line for line in r1["missing_lines"]),
            msg=r1["missing_lines"],
        )

    def test_unadvertised_ospf_interface_is_not_routed_or_reachable(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._inline_runtime(
                directory,
                "ospf-advertisement-filter",
                [
                    {"name": "R1", "kind": "router", "cli_profile": "ios"},
                    {"name": "R2", "kind": "router", "cli_profile": "ios"},
                ],
                [["R1", "Ethernet0/0", "R2", "Ethernet0/0"]],
            )
            runtime.apply_config(
                "R1",
                "interface Ethernet0/0\n"
                " ip address 10.0.0.1 255.255.255.252\n"
                " no shutdown\n"
                "router ospf 1\n"
                " network 10.0.0.0 0.0.0.3 area 0",
            )
            runtime.apply_config(
                "R2",
                "interface Ethernet0/0\n"
                " ip address 10.0.0.2 255.255.255.252\n"
                " no shutdown\n"
                "interface Ethernet0/1\n"
                " ip address 192.0.2.1 255.255.255.0\n"
                " no shutdown\n"
                "router ospf 1\n"
                " network 10.0.0.0 0.0.0.3 area 0",
            )
            self.assertTrue(runtime.network().ospf_neighbors("R1"))
            self.assertFalse(runtime.network().can_reach("R1", "192.0.2.1"))
            self.assertFalse(
                any(
                    "192.0.2.0/24" in route
                    for route in runtime.network().route_entries(
                        "R1", ospf_only=True
                    )
                )
            )

            runtime.apply_config(
                "R2",
                "router ospf 1\n network 192.0.2.0 0.0.0.255 area 0",
            )
            self.assertTrue(runtime.network().can_reach("R1", "192.0.2.1"))
            self.assertTrue(
                any(
                    "192.0.2.0/24" in route
                    for route in runtime.network().route_entries(
                        "R1", ospf_only=True
                    )
                )
            )

    def test_lacp_grading_requires_every_expected_member(self):
        runtime = self.runtime("etherchannel-lacp")
        for node in ("S1", "S2"):
            runtime.apply_config(node, self.solution("etherchannel-lacp", node))
        runtime.apply_config("S1", "interface Ethernet0/1\n shutdown")
        self.assertTrue(runtime.network().channel_status("S1", 1)["formed"])

        report = grade_lab(
            str(LABS_DIR / "etherchannel-lacp" / "lab.yaml"),
            snapshot=runtime.snapshot(),
        )
        s1 = next(item for item in report["node_results"] if item["node"] == "S1")
        self.assertFalse(s1["passed"])
        self.assertIn(
            "EtherChannel 1: expected member Ethernet0/1 is not bundled/up",
            s1["missing_lines"],
        )

    def test_unreachable_telnet_target_does_not_count_as_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, yaml_path = self._inline_runtime(
                directory,
                "telnet-unreachable",
                [
                    {"name": "PC1", "kind": "host", "cli_profile": "ios"},
                    {"name": "R1", "kind": "router", "cli_profile": "ios"},
                ],
                checks=[
                    {
                        "node": "PC1",
                        "type": "telnet_refused",
                        "target": "198.51.100.1",
                        "description": "unreachable target must not pass",
                    }
                ],
            )
            runtime.apply_config(
                "PC1",
                "interface Ethernet0/0\n"
                " ip address 192.0.2.2 255.255.255.0\n"
                " no shutdown",
            )
            runtime.apply_config(
                "R1",
                "interface Ethernet0/0\n"
                " ip address 198.51.100.1 255.255.255.0\n"
                " no shutdown\n"
                "line vty 0 4\n transport input ssh",
            )
            report = grade_lab(str(yaml_path), snapshot=runtime.snapshot())

        pc1 = next(item for item in report["node_results"] if item["node"] == "PC1")
        self.assertFalse(pc1["passed"])
        self.assertTrue(
            any("unreachable" in line for line in pc1["missing_lines"]),
            msg=pc1["missing_lines"],
        )

    def test_local_ntp_master_reports_ntp_as_clock_source(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = self._inline_runtime(
                directory,
                "local-ntp-master",
                [{"name": "R1", "kind": "router", "cli_profile": "ios"}],
            )
            runtime.apply_config("R1", "ntp master 3")
            terminal = self.manager.attach(runtime.runtime_id, "R1")
            output = self.manager.execute(terminal, "show clock detail\r")
        self.assertIn("Time source is NTP", output)

    def test_unknown_check_types_fail_instead_of_silently_passing(self):
        definition = {
            "lab": {
                "id": "unknown-check",
                "title": "Unknown check",
                "nodes": [{"name": "PC1", "device_type": "vpcs"}],
                "links": [],
                "checks": [
                    {
                        "node": "PC1",
                        "type": "magic",
                        "description": "Unsupported verification",
                    }
                ],
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            yaml_path = Path(directory) / "lab.yaml"
            yaml_path.write_text(yaml.safe_dump(definition), encoding="utf-8")
            runtime = self.manager.create(
                slug="unknown-check", yaml_path=str(yaml_path)
            )
            report = grade_lab(str(yaml_path), snapshot=runtime.snapshot())
        self.assertFalse(report["passed"])
        self.assertIn(
            "Unsupported behavioral check type",
            report["node_results"][0]["missing_lines"][0],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
