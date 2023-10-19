import hashlib
import sklearn.cluster
from tqdm import tqdm

from GIPS.utils import AEchunking, minHash, IORA
from GIPS.HH import RealTimeGen, DHH

def contents2count(chunks, vec_size):
    vector = [0] * vec_size
    for chunk in set(chunks):
        chunk_fh = int(hashlib.md5(chunk.encode()).hexdigest(),16) % vec_size
        vector[chunk_fh] += 1
    return vector

def dbscan(payloads, th):

    X = [AEchunking(payload, 3) for payload in payloads]
    vectors = [contents2count(chunks, 4096) for chunks in X]
    model = sklearn.cluster.DBSCAN(eps=1-th, min_samples=5, metric='cosine', n_jobs=None)
    model.fit(vectors)

    label_list = model.labels_
    
    return label_list

def GIPS(strings, M=16384, K=64, thetaJ=0.6, TH=0.6, cluster_num = 10):

    sum_vector = [0] * M
    big_group = []
    
    no_group_hh = RealTimeGen() # for AWL
    
    for string in tqdm(strings):

        # MV2
        chunks = AEchunking(string, W=3)
        feature = minHash(chunks, K=K)

        # JIG
        thetaC = IORA(sum_vector)
        
        count = 0
        for _hash_value in feature:
            hash_value = int(_hash_value) % M
            if sum_vector[hash_value] >= thetaC:
                count += 1
            sum_vector[hash_value] += 1

        if count >= K * thetaJ:
            big_group.append(string)
        else:
            no_group_hh.add(string)

    # SG2
    cluster_labels = dbscan(big_group, TH)

    cluster_dict = dict()
    for payload, cluster_label in zip(big_group, cluster_labels):
        
        if cluster_label == -1:
            continue
        
        if cluster_label not in cluster_dict.keys():
            cluster_dict[cluster_label] = []
        cluster_dict[cluster_label].append(payload)

    cluster_counters = []
    for cluster_label in cluster_dict.keys():
        cluster_counters.append((cluster_label, len(cluster_dict[cluster_label])))
    cluster_counters.sort(key=lambda x: -x[1])

    cluster_signatures = dict()
    for cluster_label, _ in tqdm(cluster_counters[:cluster_num]):
        
        cluster_payloads = cluster_dict[cluster_label]
        signatures = DHH(
            packets = cluster_payloads,
            k = 4,
            hh1_size = 3000,
            hh2_size = 3000,
            ratio = 0.1,
            deduplication = True,
        )

        cluster_signatures[cluster_label] = (signatures, len(cluster_payloads))

    return cluster_signatures, no_group_hh.decode2()