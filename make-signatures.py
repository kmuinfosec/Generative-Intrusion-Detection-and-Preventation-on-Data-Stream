import pickle
import configparser

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

    properties = configparser.ConfigParser()
    properties.read('config.ini')

    payload_path = properties.get('PATH', 'payload_path')
    signature_path = properties.get('PATH', 'signature_path')
    stopword_path = properties.get('PATH', 'stopword_path')

    K = properties.getint('JIG', 'K')
    M = properties.getint('JIG', 'M')
    thetaJ = properties.getfloat('JIG', 'thetaJ')

    window_size = properties.getint('SG2', 'window_size')
    vector_size = properties.getint('SG2', 'vector_size')
    eps = properties.getfloat('SG2', 'eps')
    minpts = properties.getint('SG2', 'minpts')
    ngram = properties.getint('SG2', 'ngram')
    hh1_size = properties.getint('SG2', 'hh1_size')
    hh2_size = properties.getint('SG2', 'hh2_size')
    ratio = properties.getfloat('SG2', 'ratio')

    main(payload_path=payload_path, signature_path=signature_path, stopword_path=stopword_path,
         K=K, M=M, thetaJ=thetaJ,
         window_size=window_size, vector_size=vector_size, eps=eps, minpts=minpts,
         ngram=ngram, hh1_size=hh1_size, hh2_size=hh2_size, ratio=ratio)
    
"""
TODO
- add README.md
- add docs - code document, presentation pdf
"""