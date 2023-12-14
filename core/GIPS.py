import hashlib
import sklearn
import numpy as np

from core.HH import DHH
from core.utils import AEchunking, minHash, IORA

def MV2(payloads, window_size, K, M):
    
    minhashed_virtual_vectors = []
    for payload in payloads:
        chunks = AEchunking(payload, W=window_size)
        encode_pos = minHash(chunks, K=K) % M

        vector = np.zeros(M, dtype=np.int8)
        vector[encode_pos] = 1

        minhashed_virtual_vectors.append(vector)

    return minhashed_virtual_vectors

def JIG(vectors, thetaJ):
    
    M = len(vectors[0])
    MV = np.zeros(M, dtype=np.int32)
    big_group_indices = []

    for idx, vector in vectors:

        encode_pos = set(np.nonzero(vector)[0])

        thetaC = IORA(MV)
        big_counter_pos = set(np.where(MV > thetaC)[0])

        overlap_set = encode_pos & big_counter_pos
        overlap_ratio = len(overlap_set) / len(encode_pos)

        if overlap_ratio >= thetaJ:
            big_group_indices.append(idx)
    
    return big_group_indices

def contents2count(chunks, vec_size):
    vector = [0] * vec_size
    for chunk in set(chunks):
        chunk_fh = int(hashlib.md5(chunk.encode()).hexdigest(),16) % vec_size
        vector[chunk_fh] += 1
    return vector

def SG2(payloads, window_size, vector_size, eps, minpts, ngram, hh1_size, hh2_size, ratio):
    
    # clustering
    fine_vectors = []
    for payload in payloads:
        chunks = AEchunking(payload, window_size)
        vector = np.zeros(vector_size, dtype=np.int8)
        for chunk in set(chunks):
            chunk_idx = int(hashlib.md5(chunk.encode()).hexdigest(),16) % vector_size
            vector[chunk_idx] += 1

        fine_vectors.append(vector)

    model = sklearn.cluster.DBSCAN(eps=1-eps, min_samples=minpts, metric='cosine', n_jobs=None)
    model.fit(fine_vectors)

    cluster_labels = model.labels_

    # remove anomal data, sort by frequency
    cluster_dict = dict()
    for payload, cluster_label in zip(payloads, cluster_labels):
        
        if cluster_label == -1:
            continue
        
        if cluster_label not in cluster_dict.keys():
            cluster_dict[cluster_label] = []
        cluster_dict[cluster_label].append(payload)

    cluster_counters = []
    for cluster_label in cluster_dict.keys():
        cluster_counters.append((cluster_label, len(cluster_dict[cluster_label])))
    cluster_counters.sort(key=lambda x: -x[1])

    # generate signature groups
    cluster_signatures = dict()
    for cluster_label, _ in cluster_counters:
        
        cluster_payloads = cluster_dict[cluster_label]
        signatures = DHH(
            packets = cluster_payloads,
            k = ngram,
            hh1_size = hh1_size,
            hh2_size = hh2_size,
            ratio = ratio,
            deduplication = True,
        )

        cluster_signatures[cluster_label] = (signatures, len(cluster_payloads))

    return cluster_signatures

def AWL(payloads, ngram, hh1_size, hh2_size, ratio):
    
    stopwords = DHH(
        packets = payloads,
        k = ngram,
        hh1_size = hh1_size,
        hh2_size = hh2_size,
        ratio = ratio,
        deduplication = True,
    )

    return stopwords