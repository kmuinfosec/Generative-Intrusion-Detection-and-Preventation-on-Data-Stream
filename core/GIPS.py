import numpy as np

from core.utils import AEchunking, minHash

def MV2(payloads, window_size, K, M):
    
    minhashed_virtual_vectors = []
    for payload in payloads:
        chunks = AEchunking(payload, W=3)
        encode_pos = minHash(chunks, K=K) % M

        vector = np.zeros(M, dtype=np.int8)
        vector[encode_pos] = 1

        minhashed_virtual_vectors.append(vector)

    return minhashed_virtual_vectors

def JIG(vectors, thetaJ):
    pass 

def SG2(payloads, window_size, vector_size, eps, minpts, ngram, hh1_size, hh2_size, ratio):
    pass

def AWL(payloads, ngram, hh1_size, hh2_size, ratio):
    pass