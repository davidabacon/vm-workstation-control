# VMware Workstation Web Control

This project provides a web-based interface for managing VMware Workstation virtual machines. It scans for VMX files, extracts VM details, and allows users to start or stop VMs from a browser.

~~I wrote this and then found that there is apparently something from VMware directly that I am sure must be better..
I will be checking into WSX:  
     https://knowledge.broadcom.com/external/article/310200/configuring-wsx-in-vmware-workstation.html
Fun project nevertheless.~~
Turns out that WSX was deprecated in Workstation 16.X and removed entirely from 17.X.



## Features

- **Automatic VM Discovery**: Scans a specified folder for `.vmx` files.
- **VM Details Extraction**: Retrieves OS, CPU, RAM, disk size, and MAC address from VMX files.
- **VM Control**: Start and stop virtual machines using `vmrun`.
- **Network Scanning**: Uses `nmap` to detect active IP addresses in a subnet.
- **Web UI**: A Flask-powered web interface for managing VMs.

## Screenshot

![image](https://github.com/user-attachments/assets/c82db393-63f1-4576-aede-7dc4ddc94a6a)


## Installation

### Prerequisites

- Python 3.x
- Flask (`pip install flask`)
- Nmap (`sudo apt install nmap` or `brew install nmap` on macOS)
- VMware Workstation (`vmrun` must be available in the system path)

### Clone the Repository

```sh
git clone https://github.com/davidabacon/vmware-web-control.git
cd vmware-web-control
```

### Install Dependencies

```sh
pip install -r requirements.txt
```

## Configuration

The base VM directory and network subnet are configurable:

- **Base VM Directory**: Change `BASE_VM_DIR` in `app.py` to match your VM storage path.
- **Subnet for Scanning**: Modify `SUBNET` in `app.py` to match your local network.
- **Web Port**: The web service runs on port `15000` by default.

## Usage

### Run the Application

```sh
python app.py
```

The web UI will be available at `http://localhost:15000`.

### Start/Stop a VM

- Click the "Start" button to power on a VM.
- Click "Stop" to shut it down (soft stop by default, hard stop option available).

## API Endpoints

| Endpoint            | Method | Description                            |
|---------------------|--------|----------------------------------------|
| `/`                 | GET    | Web interface                         |
| `/start_vm`        | POST   | Start a VM (requires VMX file path)    |
| `/stop_vm`         | POST   | Stop a VM (soft or hard stop)          |
| `/set_folder`      | POST   | Change the base VM directory           |

## Troubleshooting

- **Missing VMs**: Ensure `BASE_VM_DIR` is set correctly.
- **VMs Not Starting**: Check that `vmrun` is installed and in your PATH.
- **Network Scan Not Working**: Ensure `nmap` is installed and run with the necessary permissions.

## License

This project is licensed under the MIT License.

---

### Contributors
- **Your Name** (@davidabacon)
- Contributions welcome! Feel free to submit pull requests.

---

