#SETS UP OUR ENVIRONMENT

#!/usr/bin/env python3
import subprocess
import time
import os

# ----- Global Configuration -----
NETWORK_NAME = "satnet"
SUBNET = "192.168.1.0/24" #We have to define the docker network with a subnet that can communicate with the VM's NAT so that container has internet access

SATNET = "SATNET"  #Server node

# ----- Utility Function -----
def run_cmd(cmd):
    print("Running:", cmd)
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip())
    return result

# ----- Network and Container Setup Functions -----
def reset_docker():
    run_cmd("docker rm -f $(docker ps -aq)")
    run_cmd("docker network prune -f")

def create_network(name, subnet):
    result = run_cmd(f"docker network ls --filter name=^{name}$ --format '{{{{.Name}}}}'")
    if name in result.stdout.split():
        print(f"Network {name} already exists.")
    else:
        cmd = f"docker network create --driver bridge --subnet {subnet} {name}"
        run_cmd(cmd)

def initialize_containers():
    global SATNET
    create_network(NETWORK_NAME, SUBNET)

    SATNET = run_cmd(f'docker run -d --name {SATNET} --network {NETWORK_NAME} --cap-add=NET_ADMIN --privileged --entrypoint /bin/bash gns3/ubuntu:noble -c "tail -f /dev/null"').stdout.strip()

    time.sleep(0.5) #Give docker a moment to initialise a network

    # --- Install gdb and necessary C libraries ---
    run_cmd(f"docker exec {SATNET} apt-get update -y")
    run_cmd(f"docker exec {SATNET} apt-get install -y build-essential gdb libpcap-dev gcc tcpdump")

    run_cmd(f"docker cp server.c {SATNET}:/tmp/server.c")

    run_cmd(f"docker cp /mnt/VM_Shared/pcaps {SATNET}:/tmp/")

    print("Done!")

def main():
    reset_docker()
    initialize_containers()

if __name__ == "__main__":
    main()