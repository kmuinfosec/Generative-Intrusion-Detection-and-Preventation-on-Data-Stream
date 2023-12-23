import pickle
import configparser

def get_confusion_matrix(payloads, labels, signatures):
    labelset = dict()
    for payload, label in zip(payloads, labels):
        if label not in labelset.keys():
            labelset[label] = 0

        for sign, freq in signatures:
            if sign in payload:
                labelset[label] = 1

    tp = tn = fp = fn = 0
    for label, pred in labelset.items():
        if label=='unknown':
            continue
        
        true = 1
        if 'benign' in label.lower():
            true = 0
        
        if true==0 and pred==0:
            tn += 1
        elif true==0 and pred==1:
            fp += 1
        elif true==1 and pred==0:
            fn += 1
        else:
            tp += 1
    
    return tp, tn, fp, fn

if __name__ == '__main__':

    properties = configparser.ConfigParser()
    properties.read('config.ini')

    payload_path = properties.get('PATH', 'payload_path')
    label_path = properties.get('PATH', 'label_path')
    signature_path = properties.get('PATH', 'signature_path')
    stopword_path = properties.get('PATH', 'stopword_path')

    with open(payload_path, 'rb') as f:
        payloads = pickle.load(f)

    with open(label_path, 'rb') as f:
        labels = pickle.load(f)

    ## signatures 몇 개 쓸건지 필터링 필요
    with open(signature_path, 'rb') as f:
        signatures = pickle.load(f)

    ## stopword (AWL) 사용방법 필터링 추가 필요
    with open(stopword_path, 'rb') as f:
        stopwords = pickle.load(f)

    print(get_confusion_matrix(payloads, labels, signatures))