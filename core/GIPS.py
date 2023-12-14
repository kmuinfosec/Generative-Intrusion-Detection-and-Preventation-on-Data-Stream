import numpy as np

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

def SG2(payloads, window_size, vector_size, eps, minpts, ngram, hh1_size, hh2_size, ratio):
    pass

def AWL(payloads, ngram, hh1_size, hh2_size, ratio):
    pass