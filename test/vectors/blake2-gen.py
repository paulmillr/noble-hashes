import hashlib
import json

def write_file(filename, obj):
    with open('{}.json'.format(filename), 'w') as f:
        f.write(json.dumps(obj))

def digest(h, data):
    h.update(data)
    return h.hexdigest()

bytes8 = bytes([0, 1, 2, 3, 4, 5, 6, 7])

person = [None, bytes('perspers', 'ascii'), bytes8]
salt = [None, bytes('saltsalt', 'ascii'), bytes8]
key = [None, bytes('key', 'ascii'), bytes8]
data = bytes('data', 'ascii')
dkLen = {'blake2b': 64, 'blake2s': 32}

def gen():
    out = []
    for b in [hashlib.blake2s, hashlib.blake2b]:
        name = str(b).split("'")[1].split('.')[1]
        for p in person:
            for s in salt:
                for k in key:
                    for dLen in range(1, dkLen[name]+1):
                        kw = {'digest_size': dLen}
                        if p: kw['person'] = p
                        if s: kw['salt'] = s
                        if k: kw['key'] = k
                        if name == 'blake2b':
                            if 'salt' in kw:
                                kw['salt'] = kw['salt'] * 2
                            if 'person' in kw:
                                kw['person'] = kw['person'] * 2
                        result = digest(b(**kw), data)
                        vector = {'hash': name, 'digest': result, 'dkLen': dLen}
                        for i in kw:
                            if i=='digest_size': continue
                            vector[i] = kw[i].hex()
                        out.append(vector)
    write_file('blake2-python.json', out)

gen()