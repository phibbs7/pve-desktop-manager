# pve-desktop-manager
A small desktop GUI app to manage a Proxmox VE server. Written in perl.

# Dependencies
- Config
- Config::IniFiles
- Data::Dumper
- DateTime
- File::Temp
- JSON
- [PVE::APIClient::LWP](https://git.proxmox.com/?p=pve-apiclient.git;a=summary)
- Tk
- Tk::Table

# Features
- Queries and generates list for selecting a different authentication realm during login.
- Lists all VMs the user has access to, their current run status, and what node they are running on (if applicable).
- Can power on / off / force shutdown / force reset VMs.
- Can open SPICE consoles for use via remote-viewer. (Generates the needed console.vv file on the fly.) 

# Usage
To use it just run the perl script. You'll be presented with a login window.

# Known issues
- VNC console types don't work.
  - This is due to the Proxmox VE api not allowing remote-viewer to use the generated ticket (from the /api2/json/node/NODEID/qemu/VMID/vncproxy endpoint) as the password for the VNC connection.

- Containers are not currently supported.
- Linux is the only supported OS for autolaunching remote-viewer. (The location of the generated console.vv file will be displayed to the user in this case. Along with a message to open it manually.)
  - Because I'm lazy. Patches welcome!

- Holy stars Batman! That's some _badly_ written Perl code!
  - It's my first attempt at writing code in Perl. See also the "damage" comments in the code itself. (Which should be removed...)

# Acknowledgements
- Proxmox (for making their VE server and endpoint API avaiable to the public.)
