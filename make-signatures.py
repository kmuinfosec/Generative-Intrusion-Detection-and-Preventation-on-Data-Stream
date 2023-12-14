import pickle

from core.GIPS import MV2, JIG, SG2, AWL

def main(payload_path, signature_path, stopword_path,
         K, M, thetaJ,
         window_size, vector_size, eps, minpts,
         ngram, hh1_size, hh2_size, ratio):
    
    # payloads = [payload0, payload1, payload2, ...]
    with open(payload_path, 'rb') as f:
        payloads = pickle.load(f)

    # big group identification
    minhashed_virtual_vectors = MV2(payloads, window_size, K, M)
    big_group_indices = JIG(minhashed_virtual_vectors, thetaJ)

    big_group_payloads = []
    non_big_group_payloads = []

    for idx, payload in enumerate(payloads):
        if idx in big_group_indices:
            big_group_payloads.append(payload)
        else:
            non_big_group_payloads.append(payload)

    # signature group generation
    group_signatures = SG2(big_group_payloads,
                           window_size=window_size,
                           vector_size=vector_size,
                           eps=eps,
                           minpts=minpts,
                           ngram=ngram,
                           hh1_size=hh1_size,
                           hh2_size=hh2_size,
                           ratio=ratio)
    
    stopwords = AWL(non_big_group_payloads,
                    ngram=ngram,
                    hh1_size=hh1_size,
                    hh2_size=hh2_size,
                    ratio=ratio)

    # save results
    with open(signature_path, 'wb') as f:
        pickle.dump(group_signatures, f)
    with open(stopword_path, 'wb') as f:
        pickle.dump(stopwords, f)


if __name__ == '__main__':
    main(payload_path='', signature_path='', stopword_path='',
         K=64, M=2048, thetaJ=0.6,
         window_size=3, vector_size=512, eps=0.6, minpts=5,
         ngram=4, hh1_size=3000, hh2_size=3000, ratio=0.1)
    
"""
TODO
- hyperparameter configurization
- add utils.py
- add README.md
- add docs - code document, presentation pdf
- add dataset preprocess func.
- add evaluation func.
"""