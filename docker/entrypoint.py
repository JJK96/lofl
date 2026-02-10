#!/usr/bin/env python3
"""
LOFL Docker Entrypoint
Reads configuration from /etc/lofl/lofl.yaml and sets up the container environment.
"""

import os
import sys
import subprocess
import yaml

CONFIG_PATH = "/etc/lofl/lofl.yaml"
DNSMASQ_CONF_PATH = "/etc/dnsmasq.conf"
ROUTES_FILE_PATH = "/tmp/routes.txt"

# Defaults
DEFAULTS = {
    "in_interface": "tun0",
    "tun_ip": "198.18.0.1/15",
    "default_dns": "127.0.0.11",
}


def enable_ip_forwarding():
    """Enable IP forwarding in the kernel."""
    print("[+] Enabling IP forwarding")
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except PermissionError:
        print("[!] Warning: Could not enable IP forwarding (permission denied)", file=sys.stderr)
        print("    Ensure the host has ip_forward enabled or run with --privileged", file=sys.stderr)


def load_config():
    """Load configuration from YAML file."""
    if not os.path.exists(CONFIG_PATH):
        print(f"Error: Configuration file not found: {CONFIG_PATH}", file=sys.stderr)
        print("Please mount your configuration file to /etc/lofl/lofl.yaml", file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    # Apply defaults
    for key, value in DEFAULTS.items():
        if key not in config:
            config[key] = value

    # Validate required fields
    required = ["victim_domains", "victim_dns", "proxy"]
    missing = [field for field in required if field not in config]
    if missing:
        print(f"Error: Missing required configuration fields: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    return config


def generate_dnsmasq_conf(config):
    """Generate dnsmasq.conf from configuration."""
    lines = [
        "no-resolv",
        "",
        "# Port",
        "port=5353",
        "",
        "# Victim network DNS server",
    ]

    for domain in config["victim_domains"]:
        lines.append(f"server=/{domain}/{config['victim_dns']}")

    lines.append(f"server=/{config['victim_dns']}.in-addr.arpa/{config['victim_dns']}")
    lines.append("")
    lines.append("# Default DNS server")
    lines.append(f"server={config['default_dns']}")

    with open(DNSMASQ_CONF_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Generated {DNSMASQ_CONF_PATH}")


def create_tun_interface(config):
    """Create the TUN interface."""
    tun_name = config["in_interface"]
    tun_ip = config.get("tun_ip", DEFAULTS["tun_ip"])

    print(f"[+] Creating TUN interface: {tun_name}")

    # Create TUN interface
    result = subprocess.run(
        ["ip", "tuntap", "add", "mode", "tun", "dev", tun_name],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Check if it already exists
        if "File exists" not in result.stderr:
            print(f"Error creating TUN interface: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] TUN interface {tun_name} already exists")

    # Assign IP address
    print(f"[+] Assigning IP {tun_ip} to {tun_name}")
    subprocess.run(
        ["ip", "address", "add", tun_ip, "dev", tun_name]
    )

    # Bring interface up
    print(f"[+] Bringing up interface {tun_name}")
    subprocess.run(["ip", "link", "set", "dev", tun_name, "up"], check=True)


def setup_iptables(config):
    """Set up iptables NAT rules."""
    tun_name = config["in_interface"]
    network_interface = config.get("network_interface")

    # In local mode (bridge network), we need to find the default interface
    if not network_interface:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout:
            # Parse: default via X.X.X.X dev eth0
            parts = result.stdout.split()
            if "dev" in parts:
                network_interface = parts[parts.index("dev") + 1]
        if not network_interface:
            network_interface = "eth0"

    print(f"[+] Setting up NAT: {network_interface} -> {tun_name}")

    # MASQUERADE for outgoing traffic
    subprocess.run([
        "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-o", tun_name, "-j", "MASQUERADE"
    ])

    # Forward established connections back
    subprocess.run([
        "iptables", "-A", "FORWARD",
        "-i", tun_name, "-o", network_interface,
        "-m", "state", "--state", "RELATED,ESTABLISHED",
        "-j", "ACCEPT"
    ])

    # Forward new connections to TUN
    subprocess.run([
        "iptables", "-A", "FORWARD",
        "-i", network_interface, "-o", tun_name,
        "-j", "ACCEPT"
    ])


def setup_routes(config):
    """Set up routes for target networks."""
    routes = config.get("routes", [])
    if not routes:
        print("[*] No routes configured")
        return

    tun_name = config["in_interface"]
    # Extract gateway IP from tun_ip (e.g., 198.18.0.1/15 -> 198.18.0.1)
    gateway_ip = config.get("tun_ip", DEFAULTS["tun_ip"]).split("/")[0]

    print(f"[+] Adding {len(routes)} routes via {gateway_ip}")

    for route in routes:
        print(f"    Route: {route}")
        subprocess.run([
            "ip", "route", "add", route,
            "via", gateway_ip, "dev", tun_name
        ], capture_output=True)


def setup_dns():
    with open('/etc/resolv.conf', 'w') as f:
        f.write("nameserver 127.0.0.1")


def set_environment_variables(config):
    """Set environment variables for supervisord."""
    # TUN interface name
    os.environ["TUN_INTERFACE"] = config["in_interface"]

    # SOCKS proxy
    os.environ["PROXY"] = config["proxy"]

    # First victim domain for cldaproxy
    os.environ["VICTIM_DOMAIN"] = config["victim_domains"][0]


def start_supervisord():
    """Start supervisord to manage services."""
    print("[+] Starting supervisord")
    print("-" * 60)
    os.execvp("supervisord", ["supervisord"])


def main():
    print("=" * 60)
    print("LOFL - Living Off the Foreign Land")
    print("Docker Container Entrypoint")
    print("=" * 60)

    # Enable IP forwarding
    # enable_ip_forwarding()

    # Load configuration
    print("[+] Loading configuration")
    config = load_config()

    # Generate dnsmasq configuration
    generate_dnsmasq_conf(config)

    # Create TUN interface
    create_tun_interface(config)

    # Set up iptables
    setup_iptables(config)

    # Set up routes
    setup_routes(config)

    # Set up DNS
    setup_dns()

    # Set environment variables for supervisord
    set_environment_variables(config)

    # Start supervisord (replaces this process)
    start_supervisord()


if __name__ == "__main__":
    main()
