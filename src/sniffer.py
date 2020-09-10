from collections import Counter
from scapy.all import sniff

# Create a Packet Counter
packet_counts = Counter()

# Define our Custom Action function


def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])
    return f"Packet #{sum(packet_counts.values())}: {packet[0][1].src} ==> {packet[0][1].dst}"


def test():
    # Setup sniff, filtering for IP traffic
    # sniff(filter="ip", monitor=True, prn=custom_action, count=100)
    sniff(filter="ip", prn=custom_action, count=10)

    # Print out packet count per A <--> Z address pair
    print("\n".join(
        f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))


if __name__ == "__main__":
    test()
