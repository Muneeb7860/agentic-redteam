"""
SwishOS OCI Container & Kernel Isolation Physics Generator
Generates hardened gVisor runsc, cgroup memory limits, read-only root, and iptables metadata drop rules.
Defeats Container Escapes & Cloud Metadata SSRF Exfiltration.
"""

from __future__ import annotations
import json
from typing import Any, Dict

def generate_gvisor_docker_compose_service(
    service_name: str = "agent-runtime-enclave",
    image: str = "swishos/agent-executor:latest",
    memory_limit_mb: int = 256,
    pids_limit: int = 20
) -> Dict[str, Any]:
    """
    Generates a production Docker Compose service dictionary configured with
    gVisor user-space kernel isolation (`runsc`), read-only root, and tmpfs caps.
    """
    return {
        service_name: {
            "image": image,
            "runtime": "runsc",  # gVisor User-Space Virtual Kernel
            "read_only": True,
            "tmpfs": [
                "/tmp:rw,noexec,nosuid,size=64m"  # Memory-only /tmp with zero binary execution capability
            ],
            "security_opt": [
                "no-new-privileges:true",
                "seccomp=unconfined"  # System calls handled safely inside gVisor
            ],
            "deploy": {
                "resources": {
                    "limits": {
                        "cpus": "0.50",
                        "memory": f"{memory_limit_mb}M"
                    }
                }
            },
            "pids_limit": pids_limit,
            "cap_drop": ["ALL"],  # Drop all ambient Linux capabilities
            "cap_add": ["NET_BIND_SERVICE"]
        }
    }

def generate_iptables_metadata_drop_commands() -> list[str]:
    """
    Generates Linux iptables rules to drop all egress packets to the cloud metadata IP (169.254.169.254).
    Prevents IAM role and cloud token exfiltration.
    """
    return [
        "iptables -A OUTPUT -d 169.254.169.254 -j DROP",
        "iptables -A OUTPUT -d 169.254.170.2 -j DROP",  # AWS ECS Task Metadata IP
        "ip6tables -A OUTPUT -d fd00:ec2::254 -j DROP"  # IPv6 AWS Metadata IP
    ]
