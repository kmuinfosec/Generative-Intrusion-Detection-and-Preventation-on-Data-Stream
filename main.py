import pickle

from GIPS.core import GIPS

def main(pcap_pkl_path, save_path):
    with open(pcap_pkl_path, 'rb') as f:
        data = pickle.load(f)

    payloads = []
    for payload, label in data:
        payloads.append(payload)

    cluster_signatures, no_group_signatures = GIPS(strings=payloads, thetaJ=0.6, TH=0.6)

    with open(save_path, 'wb') as f:
        pickle.dump((cluster_signatures, no_group_signatures), f)

if __name__ == '__main__':
    main("pcap_pkl_path", "save_path")

    