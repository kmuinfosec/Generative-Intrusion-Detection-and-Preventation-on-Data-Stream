import math
import datasketch

def AEchunking(doc, W):
    chunks = []
    window = str()
    window_count = 0
    
    for i, word in enumerate(doc):
        if window_count > W:
            chunks.append(window)
            window = str()
            window_count = 0
        elif word > doc[i - window_count]:
            window_count = 0
        window += word
        window_count += 1
        
    if len(window)!=0:
        chunks.append(window)
    return chunks

def minHash(chunks, K, SEED=42):
    signature = datasketch.minhash.MinHash(num_perm=K, seed=SEED)
    for chunk in chunks:
        signature.update(chunk.encode())
    return signature.digest()

def IORA(sum_vector_):
    sum_vector = sorted(sum_vector_, reverse=True)
    total = sum(sum_vector)
    
    for idx in range(0, len(sum_vector)):
        length = len(sum_vector) - idx
        mean = total / length
        sigma = math.sqrt(mean * (length - 1) / length)
        
        thetaC = mean + 6 * sigma
        if sum_vector[idx] <= thetaC:
            break

        total -= sum_vector[idx]
    return thetaC