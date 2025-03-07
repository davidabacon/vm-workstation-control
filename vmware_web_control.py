import os
import re
import json
import nmap
import subprocess
import hashlib
import concurrent.futures
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
BASE_VM_DIR = "/storage/500SDD/VMS"
SUBNET = "192.168.2.0/24"
PORT = 15000

def hash_id(value):
    """Generate a short unique ID from a string."""
    return hashlib.md5(value.encode()).hexdigest()[:8]  # 8-character hash

app.jinja_env.filters["hash_id"] = hash_id  # Register Jinja filter

def get_vmx_files(base_dir):
    """Scan recursively for VMX files."""
    vmx_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".vmx"):
                vmx_files.append(os.path.join(root, file))
    return vmx_files

def parse_vmx(vmx_path):
    """Extract VM details from VMX file, including MAC address."""
    vm_details = {
        "name": os.path.splitext(os.path.basename(vmx_path))[0],  # Remove .vmx extension
        "path": vmx_path,
        "cpu": "Unknown",
        "ram": "Unknown",
        "os": "Unknown",
        "disk_size": "Unknown",
        "mac_address": "Unknown"
    }
    try:
        with open(vmx_path, "r") as file:
            for line in file:
                if "guestOS" in line:
                    vm_details["os"] = line.split('=')[1].strip().strip('"')
                elif "memsize" in line:
                    vm_details["ram"] = f"{line.split('=')[1].strip().strip('"')} MB"
                elif "numvcpus" in line:
                    vm_details["cpu"] = f"{line.split('=')[1].strip().strip('"')} vCPUs"
                elif "scsi0:0.fileName" in line or "ide0:0.fileName" in line:
                    vmdk_path = os.path.join(os.path.dirname(vmx_path), line.split('=')[1].strip().strip('"'))
                    vm_details["disk_size"] = get_vmdk_size(vmdk_path)
                elif "ethernet0.generatedAddress" in line or "ethernet0.address" in line:
                    vm_details["mac_address"] = line.split('=')[1].strip().strip('"')
    except Exception as e:
        print(f"Error parsing {vmx_path}: {e}")
    return vm_details

def get_vmdk_size(vmdk_path):
    """Get actual disk size from a VMDK file, including referenced flat files."""
    if not os.path.exists(vmdk_path):
        return "Unknown"

    # Check if it's a descriptor file
    try:
        with open(vmdk_path, "r") as file:
            for line in file:
                match = re.search(r'RW \d+ SPARSE "(.*?)"', line) or re.search(r'RW \d+ FLAT "(.*?)"', line)
                if match:
                    flat_vmdk_path = os.path.join(os.path.dirname(vmdk_path), match.group(1))
                    if os.path.exists(flat_vmdk_path):
                        size_bytes = os.path.getsize(flat_vmdk_path)
                        return f"{size_bytes / (1024**3):.2f} GB"  # Convert to GB
    except Exception as e:
        print(f"Error parsing VMDK descriptor {vmdk_path}: {e}")

    # If it's a monolithic VMDK (not just a descriptor), use its own size
    try:
        size_bytes = os.path.getsize(vmdk_path)
        return f"{size_bytes / (1024**3):.2f} GB"
    except Exception:
        return "Unknown"

def get_running_vms():
    """Retrieve currently running VMs from vmrun output."""
    try:
        output = subprocess.run(["vmrun", "list"], capture_output=True, text=True)
        running_vm_paths = output.stdout.splitlines()[1:]  # Skip first line

        return set(running_vm_paths)  # Store full VMX paths
    except Exception as e:
        print(f"Error getting running VMs: {e}")
        return set()

import os

def find_common_prefix(path1, path2):
    """Find the longest common prefix between two paths."""
    parts1 = path1.split(os.sep)
    parts2 = path2.split(os.sep)

    common_parts = []
    for p1, p2 in zip(parts1, parts2):
        if p1 == p2:
            common_parts.append(p1)
        else:
            break
    return os.sep.join(common_parts)

def consolidate_directories(folders):
    """Consolidate directories into their highest necessary common path."""
    if not folders:
        return []

    folders = sorted(set(folders))  # Normalize and remove duplicates
    consolidated = []

    # Start with the first directory in the list
    current_group = [folders[0]]
    current_prefix = folders[0]  # This will track the current common prefix

    for i in range(1, len(folders)):
        # Find the common prefix between the current group's prefix and the next folder
        common_prefix = find_common_prefix(current_prefix, folders[i])

        # Check if the common prefix is at least 3 parts deep (to avoid merging too shallow paths like "/storage")
        if common_prefix and len(common_prefix.split(os.sep)) > 2:
            current_group.append(folders[i])
            current_prefix = common_prefix  # Update the current common prefix
        else:
            # When common prefix is too shallow, finalize the current group and start a new one
            consolidated.append(current_prefix)
            current_group = [folders[i]]  # Start a new group with the current folder
            current_prefix = folders[i]  # Update to the new directory's prefix

    # Don't forget to add the last group
    consolidated.append(current_prefix)

    return consolidated

def get_running_vm_folders(running_vms):
    """Extract and consolidate unique directories where running VMs are located."""
    running_folders = set(os.path.dirname(vmx) for vmx in running_vms)
    consolidated = consolidate_directories(running_folders)

    print(f"Consolidated Folders: {consolidated}")  # Debugging
    return consolidated

def scan_ip_addresses():
    """Scan network for active IP addresses in a separate thread."""
    def run_scan():
        nm = nmap.PortScanner()
        ip_map = {}
        try:
            nm.scan(hosts=SUBNET, arguments="-sn")  # Ping scan only
            for host in nm.all_hosts():
                if "ipv4" in nm[host]["addresses"]:
                    ip_map[nm[host]["hostnames"][0] if nm[host]["hostnames"] else host] = nm[host]["addresses"]["ipv4"]
        except Exception as e:
            print(f"Error scanning network: {e}")
        return ip_map

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(run_scan)
        return future.result()

@app.route("/")
def index():
    """Main webpage route."""
    running_vms = get_running_vms()  # Get running VMs (from vmrun)
    running_folders = get_running_vm_folders(running_vms)  # Get directories of running VMs

    # Get all discovered VMX files in BASE_VM_DIR
    discovered_vms = get_vmx_files(BASE_VM_DIR)

    # Ensure all running VMs are included
    all_vms = set(discovered_vms) | running_vms  # Union of both sets

    vms = []
    for vmx in all_vms:
        details = parse_vmx(vmx)
        details["status"] = "Running" if vmx in running_vms else "Stopped"
        vms.append(details)

    print(f"Final VM list sent to template: {vms}")  # Debugging

    return render_template("index.html", vms=vms, running_folders=running_folders)

@app.route("/set_folder", methods=["POST"])
def set_folder():
    """Update the VM base folder and rescan VMs."""
    global BASE_VM_DIR
    data = request.get_json()
    new_folder = data.get("folder")

    if os.path.exists(new_folder):
        BASE_VM_DIR = new_folder
        #print(f"Folder changed to: {BASE_VM_DIR}")  # Debugging
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Folder does not exist"})


@app.route("/start_vm", methods=["POST"])
def start_vm():
    """Start a VM"""
    data = request.get_json()
    vmx_path = data.get("vmx_path")

    if not vmx_path:
        return jsonify({"success": False, "error": "VM path missing"}), 400

    try:
        result = subprocess.run(["vmrun", "start", vmx_path, "nogui"], capture_output=True, text=True)

        if result.returncode == 0:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": result.stderr.strip()}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/stop_vm", methods=["POST"])
def stop_vm():
    """Stop a running VM"""
    data = request.get_json()
    vmx_path = data.get("vmx_path")
    hard_stop = data.get("hard_stop", False)  # Default to soft stop

    if not vmx_path:
        return jsonify({"success": False, "error": "VM path missing"}), 400

    stop_method = "hard" if hard_stop else ""

    #print(f"Stopping VM: {vmx_path} with method: {stop_method}")  # Debug log

    try:
        if stop_method:
            result = subprocess.run(["vmrun", "stop", vmx_path, stop_method], capture_output=True, text=True)
        else:
            result = subprocess.run(["vmrun", "stop", vmx_path], capture_output=True, text=True)

        #print(f"VMrun output: {result.stdout}")
        #print(f"VMrun error: {result.stderr}")

        if result.returncode == 0:
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": result.stderr.strip()}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)

