#!/usr/bin/env python3
"""
NHI Security Testbed - Scenario Runner
NDC Security 2026 - "Who Gave the Agent Admin Rights?!"

Executes attack scenarios and validates Wazuh detection.
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


@dataclass
class ScenarioResult:
    """Result of a scenario execution"""
    scenario_id: str
    name: str
    success: bool
    phases_executed: int
    phases_total: int
    alerts_expected: List[str]
    alerts_found: List[str]
    duration: float
    errors: List[str]


class WazuhClient:
    """Client for interacting with Wazuh API"""

    def __init__(self, host: str = "localhost", port: int = 55000,
                 username: str = "wazuh-wui", password: str = "MyS3cr3tP@ssw0rd"):
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.token = None
        self.token_expiry = None

    def authenticate(self) -> bool:
        """Authenticate with Wazuh API"""
        try:
            response = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('data', {}).get('token')
                self.token_expiry = datetime.now() + timedelta(minutes=15)
                return True
            return False
        except Exception as e:
            logger.error(f"Wazuh authentication failed: {e}")
            return False

    def get_headers(self) -> Dict[str, str]:
        """Get authenticated headers"""
        if not self.token or (self.token_expiry and datetime.now() > self.token_expiry):
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def query_alerts(self, rule_ids: List[str] = None,
                     minutes: int = 5, limit: int = 100) -> List[Dict]:
        """Query recent alerts from Wazuh"""
        try:
            headers = self.get_headers()
            params = {
                "limit": limit,
                "sort": "-timestamp"
            }

            response = requests.get(
                f"{self.base_url}/alerts",
                headers=headers,
                params=params,
                verify=False,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                alerts = data.get('data', {}).get('affected_items', [])

                # Filter by rule IDs if specified
                if rule_ids:
                    alerts = [a for a in alerts
                             if str(a.get('rule', {}).get('id')) in rule_ids]

                return alerts
            return []
        except Exception as e:
            logger.error(f"Failed to query alerts: {e}")
            return []


class ScenarioRunner:
    """Executes NHI attack scenarios"""

    def __init__(self, scenarios_dir: str = "scenarios",
                 wazuh_client: Optional[WazuhClient] = None):
        self.scenarios_dir = Path(scenarios_dir)
        self.wazuh = wazuh_client or WazuhClient()
        self.results: List[ScenarioResult] = []

    def load_scenario(self, scenario_path: Path) -> Optional[Dict]:
        """Load scenario from JSON file"""
        try:
            with open(scenario_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load scenario {scenario_path}: {e}")
            return None

    def list_scenarios(self) -> List[Dict]:
        """List all available scenarios"""
        scenarios = []
        for category_dir in sorted(self.scenarios_dir.iterdir()):
            if category_dir.is_dir() and category_dir.name.startswith('category-'):
                for scenario_file in sorted(category_dir.glob('*.json')):
                    scenario = self.load_scenario(scenario_file)
                    if scenario:
                        scenarios.append({
                            'id': scenario.get('id'),
                            'name': scenario.get('name'),
                            'category': scenario.get('category'),
                            'difficulty': scenario.get('difficulty'),
                            'path': str(scenario_file)
                        })
        return scenarios

    def execute_action(self, action: Dict, container: str = None) -> Dict:
        """Execute a single action from a scenario phase"""
        action_type = action.get('type')
        result = {'success': False, 'output': '', 'error': ''}

        try:
            if action_type == 'command':
                cmd = action.get('command')
                if container:
                    full_cmd = f"docker exec {container} {cmd}"
                else:
                    full_cmd = cmd

                logger.info(f"Executing: {cmd[:50]}...")
                proc = subprocess.run(
                    full_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                result['output'] = proc.stdout + proc.stderr
                result['success'] = proc.returncode == 0

            elif action_type == 'http_request':
                url = action.get('target')
                method = action.get('method', 'GET').upper()
                headers = action.get('headers', {})

                logger.info(f"HTTP {method}: {url}")

                if method == 'GET':
                    response = requests.get(url, headers=headers, timeout=10, verify=False)
                elif method == 'POST':
                    response = requests.post(url, headers=headers,
                                            json=action.get('body'), timeout=10, verify=False)
                else:
                    response = requests.request(method, url, headers=headers, timeout=10, verify=False)

                result['output'] = response.text
                result['status_code'] = response.status_code

                expected_status = action.get('expected_status')
                if expected_status:
                    result['success'] = response.status_code == expected_status
                else:
                    result['success'] = response.ok

            elif action_type == 'file_read':
                target = action.get('target')
                if container:
                    cmd = f"docker exec {container} cat {target}"
                    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    result['output'] = proc.stdout
                    result['success'] = proc.returncode == 0
                else:
                    with open(target, 'r') as f:
                        result['output'] = f.read()
                    result['success'] = True

            elif action_type == 'prompt':
                # AI agent prompt - log for manual execution
                content = action.get('content')
                logger.info(f"AI Prompt: {content[:50]}...")
                result['output'] = f"Manual execution required: {content}"
                result['success'] = True

            else:
                result['error'] = f"Unknown action type: {action_type}"

        except subprocess.TimeoutExpired:
            result['error'] = "Command timed out"
        except Exception as e:
            result['error'] = str(e)

        # Check expected content
        if result['success'] and 'expected_response_contains' in action:
            expected = action['expected_response_contains']
            if isinstance(expected, str):
                expected = [expected]
            result['success'] = all(exp in result['output'] for exp in expected)

        return result

    def execute_phase(self, phase: Dict, scenario: Dict) -> Dict:
        """Execute a scenario phase"""
        phase_name = phase.get('name')
        is_critical = phase.get('critical', False)
        container = scenario.get('demo_script', {}).get('container')

        logger.info(f"{Colors.CYAN}▶ Phase: {phase_name}{Colors.RESET}")
        if is_critical:
            logger.info(f"{Colors.RED}  [CRITICAL PHASE]{Colors.RESET}")

        results = []
        for action in phase.get('actions', []):
            result = self.execute_action(action, container)
            results.append(result)

            status = f"{Colors.GREEN}✓{Colors.RESET}" if result['success'] else f"{Colors.RED}✗{Colors.RESET}"
            logger.info(f"  {status} {action.get('type')}: {result.get('output', '')[:50]}...")

            if result.get('error'):
                logger.warning(f"    Error: {result['error']}")

        return {
            'name': phase_name,
            'critical': is_critical,
            'actions': results,
            'success': all(r['success'] for r in results)
        }

    def run_scenario(self, scenario_id: str, dry_run: bool = False,
                     validate_alerts: bool = True) -> ScenarioResult:
        """Execute a complete scenario"""
        # Find scenario file
        scenario_path = None
        for category_dir in self.scenarios_dir.iterdir():
            if category_dir.is_dir():
                for f in category_dir.glob(f'*{scenario_id.lower()}*.json'):
                    scenario_path = f
                    break

        if not scenario_path:
            logger.error(f"Scenario {scenario_id} not found")
            return ScenarioResult(
                scenario_id=scenario_id,
                name="Unknown",
                success=False,
                phases_executed=0,
                phases_total=0,
                alerts_expected=[],
                alerts_found=[],
                duration=0,
                errors=["Scenario not found"]
            )

        scenario = self.load_scenario(scenario_path)
        if not scenario:
            return ScenarioResult(
                scenario_id=scenario_id,
                name="Unknown",
                success=False,
                phases_executed=0,
                phases_total=0,
                alerts_expected=[],
                alerts_found=[],
                duration=0,
                errors=["Failed to load scenario"]
            )

        # Print scenario header
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}Scenario: {scenario['id']} - {scenario['name']}{Colors.RESET}")
        print(f"Category: {scenario['category']}")
        print(f"Difficulty: {scenario['difficulty']}")
        print(f"MITRE ATT&CK: {', '.join(t['id'] for t in scenario.get('mitre_attack', {}).get('techniques', []))}")
        print(f"{'='*60}\n")

        if dry_run:
            print(f"{Colors.YELLOW}[DRY RUN - No actions will be executed]{Colors.RESET}\n")
            for phase in scenario.get('phases', []):
                print(f"Phase: {phase['name']}")
                for action in phase.get('actions', []):
                    print(f"  - {action['type']}: {action.get('target', action.get('command', ''))[:50]}")
            return ScenarioResult(
                scenario_id=scenario_id,
                name=scenario['name'],
                success=True,
                phases_executed=0,
                phases_total=len(scenario.get('phases', [])),
                alerts_expected=[],
                alerts_found=[],
                duration=0,
                errors=[]
            )

        # Execute phases
        start_time = time.time()
        phases = scenario.get('phases', [])
        phase_results = []
        errors = []

        for phase in phases:
            try:
                result = self.execute_phase(phase, scenario)
                phase_results.append(result)
                if not result['success']:
                    errors.append(f"Phase '{phase['name']}' failed")
            except Exception as e:
                errors.append(f"Phase '{phase['name']}' error: {e}")

        duration = time.time() - start_time

        # Validate alerts
        alerts_expected = [str(a['rule_id']) for a in scenario.get('expected_wazuh_alerts', [])]
        alerts_found = []

        if validate_alerts and alerts_expected:
            logger.info(f"\n{Colors.CYAN}Validating Wazuh alerts...{Colors.RESET}")
            time.sleep(2)  # Wait for alerts to propagate

            found_alerts = self.wazuh.query_alerts(rule_ids=alerts_expected, minutes=5)
            alerts_found = list(set(str(a.get('rule', {}).get('id')) for a in found_alerts))

            for rule_id in alerts_expected:
                if rule_id in alerts_found:
                    print(f"  {Colors.GREEN}✓{Colors.RESET} Rule {rule_id} triggered")
                else:
                    print(f"  {Colors.RED}✗{Colors.RESET} Rule {rule_id} not found")

        # Create result
        phases_executed = sum(1 for r in phase_results if r['success'])
        success = phases_executed == len(phases) and (
            not validate_alerts or set(alerts_expected) <= set(alerts_found)
        )

        result = ScenarioResult(
            scenario_id=scenario['id'],
            name=scenario['name'],
            success=success,
            phases_executed=phases_executed,
            phases_total=len(phases),
            alerts_expected=alerts_expected,
            alerts_found=alerts_found,
            duration=duration,
            errors=errors
        )

        self.results.append(result)

        # Print summary
        print(f"\n{Colors.BOLD}Results:{Colors.RESET}")
        status = f"{Colors.GREEN}PASSED{Colors.RESET}" if success else f"{Colors.RED}FAILED{Colors.RESET}"
        print(f"  Status: {status}")
        print(f"  Phases: {phases_executed}/{len(phases)}")
        print(f"  Alerts: {len(alerts_found)}/{len(alerts_expected)}")
        print(f"  Duration: {duration:.2f}s")

        return result

    def run_all_scenarios(self, category: str = None, dry_run: bool = False) -> List[ScenarioResult]:
        """Run all scenarios (optionally filtered by category)"""
        scenarios = self.list_scenarios()

        if category:
            scenarios = [s for s in scenarios if category.lower() in s['category'].lower()]

        results = []
        for scenario in scenarios:
            result = self.run_scenario(scenario['id'], dry_run=dry_run)
            results.append(result)

        return results

    def generate_report(self, output_file: str = None) -> str:
        """Generate execution report"""
        report = []
        report.append("=" * 60)
        report.append("NHI SECURITY TESTBED - EXECUTION REPORT")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 60)
        report.append("")

        # Summary
        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        report.append(f"SUMMARY: {passed}/{total} scenarios passed")
        report.append("")

        # Details
        for result in self.results:
            status = "✓ PASS" if result.success else "✗ FAIL"
            report.append(f"{status} | {result.scenario_id} - {result.name}")
            report.append(f"       Phases: {result.phases_executed}/{result.phases_total}")
            report.append(f"       Alerts: {len(result.alerts_found)}/{len(result.alerts_expected)}")
            if result.errors:
                for error in result.errors:
                    report.append(f"       Error: {error}")
            report.append("")

        report_text = "\n".join(report)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            logger.info(f"Report saved to {output_file}")

        return report_text


def main():
    parser = argparse.ArgumentParser(
        description="NHI Security Testbed - Scenario Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List all scenarios:
    python runner.py --list

  Run a specific scenario:
    python runner.py --run S2-01

  Run all scenarios in a category:
    python runner.py --category cloud

  Dry run (show actions without executing):
    python runner.py --run S2-01 --dry-run

  Generate report:
    python runner.py --run-all --report report.txt
        """
    )

    parser.add_argument('--list', action='store_true', help='List available scenarios')
    parser.add_argument('--run', metavar='ID', help='Run specific scenario by ID')
    parser.add_argument('--run-all', action='store_true', help='Run all scenarios')
    parser.add_argument('--category', metavar='CAT', help='Filter by category')
    parser.add_argument('--dry-run', action='store_true', help='Show actions without executing')
    parser.add_argument('--no-validate', action='store_true', help='Skip Wazuh alert validation')
    parser.add_argument('--report', metavar='FILE', help='Save report to file')
    parser.add_argument('--scenarios-dir', default='scenarios', help='Scenarios directory')
    parser.add_argument('--wazuh-host', default='localhost', help='Wazuh manager host')
    parser.add_argument('--wazuh-port', type=int, default=55000, help='Wazuh API port')

    args = parser.parse_args()

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Initialize
    wazuh = WazuhClient(host=args.wazuh_host, port=args.wazuh_port)
    runner = ScenarioRunner(scenarios_dir=args.scenarios_dir, wazuh_client=wazuh)

    if args.list:
        scenarios = runner.list_scenarios()
        print(f"\n{Colors.BOLD}Available Scenarios:{Colors.RESET}\n")
        current_category = None
        for s in scenarios:
            if s['category'] != current_category:
                current_category = s['category']
                print(f"\n{Colors.CYAN}{current_category}{Colors.RESET}")
            print(f"  {s['id']:8} {s['name'][:45]:45} [{s['difficulty']}]")
        print()

    elif args.run:
        runner.run_scenario(
            args.run,
            dry_run=args.dry_run,
            validate_alerts=not args.no_validate
        )

    elif args.run_all:
        runner.run_all_scenarios(category=args.category, dry_run=args.dry_run)

        if args.report:
            runner.generate_report(args.report)
        else:
            print(runner.generate_report())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
