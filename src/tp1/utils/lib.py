from scapy.all import get_if_list, get_if_addr



def choose_interface() -> str:
    """
    Return network interface and input user choice
    """
    interfaces = get_if_list()

    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "N/A"
        print(f"  [{i}] {iface}  ({ip})")

    while True:
        entry = input("\nSelect interface number: ").strip()
        if entry.isdigit() and int(entry) < len(interfaces):
            interface = interfaces[int(entry)]
            print(f"Selected interface: {interface}\n")
            return interface
        print(f"Please enter a number between 0 and {len(interfaces) - 1}.")
