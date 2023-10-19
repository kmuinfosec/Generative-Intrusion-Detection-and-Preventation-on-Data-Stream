from collections import OrderedDict

class HeavyHitter:

    def __init__(self, vector_size: int = 512) -> None:
        self.vector_size = vector_size
        self.items = dict()
        self.inverted_items = dict()
        self.alpha = 0

    def update(self, item) -> int:

        if item in self.items.keys():
            count = self.items[item]
            self.items[item] += 1

            self.inverted_items[count].pop(item)
            if len(self.inverted_items[count]) == 0:
                if self.alpha == count:
                    self.alpha += 1
                del self.inverted_items[count]

            if count + 1 not in self.inverted_items.keys():
                self.inverted_items[count + 1] = OrderedDict()
            self.inverted_items[count + 1][item] = None

            return self.items[item]

        elif len(self.items) < self.vector_size:
            self.items[item] = 1
            if 1 not in self.inverted_items.keys():
                self.inverted_items[1] = OrderedDict()
            self.inverted_items[1][item] = None
            self.alpha = 1
            return 0

        # replace
        
        smallest_key = self.inverted_items[self.alpha].popitem(last=False)
        self.items.pop(smallest_key[0])

        self.items[item] = self.alpha + 1

        if self.alpha + 1 not in self.inverted_items.keys():
            self.inverted_items[self.alpha + 1] = OrderedDict()
        self.inverted_items[self.alpha + 1][item] = None

        if len(self.inverted_items[self.alpha]) == 0:
            del self.inverted_items[self.alpha]
            while not (self.alpha in self.inverted_items):
                self.alpha += 1

        return 0

    def fixSubstringFrequency(self) -> None:
        keys = list(self.items.keys())
        keys.sort(key=lambda x: len(x))

        for idx, string1 in enumerate(keys):
            for string2 in keys[idx:]:
                if string1 != string2 and string1 in string2:
                    self.items[string1] += self.items[string2]

def DHH(
    packets: list,
    k: int = 4,
    hh1_size: int = 512,
    hh2_size: int = 512,
    ratio: float = 0.8,
    deduplication: bool = False,
):

    heavy_hitter1, heavy_hitter2 = HeavyHitter(hh1_size), HeavyHitter(hh2_size)

    for packet in packets:

        signset = set()

        s_temp = ""
        temp_count = 0

        h = len(packet)
        for i in range(h - k + 1):
            chunk = packet[i : i + k]
            count = heavy_hitter1.update(chunk)
            if count > 0:  # case : chunk is in heavy_hiter_1 already
                if s_temp == "":
                    s_temp = chunk
                    temp_count = count
                else:
                    if count > ratio * temp_count:
                        s_temp += packet[i + k - 1]
                        temp_count = count
                    else:
                        # reset
                        if s_temp != "" and s_temp not in signset:
                            heavy_hitter2.update(s_temp)
                            if deduplication:
                                signset.add(s_temp)
                        s_temp = chunk
                        temp_count = count
            else:
                if s_temp != "" and s_temp not in signset:
                    heavy_hitter2.update(s_temp)
                    if deduplication:
                        signset.add(s_temp)
                # reset temp_count and string
                temp_count = 0
                s_temp = ""

        ### append code
        if s_temp != "" and s_temp not in signset:
            heavy_hitter2.update(s_temp)

    heavy_hitter2.fixSubstringFrequency()
    return sorted(list(heavy_hitter2.items.items()), key=lambda x: -x[1])

class RealTimeGen:
    def __init__(self):
        self.hh1 = HeavyHitter(3000)
        self.hh2 = HeavyHitter(3000)
        self.hh3 = HeavyHitter(3000)
        self.counter2 = 0
        self.k = 4
        self.ratio = 0.1

    def add(self, packet):
        s_temp = ''
        temp_counter = 0
        strings_counter = 0
        signature_set = set()
        local_signset = set()
        deduplication = True

        h = len(packet)
        for i in range(h - self.k + 1):
            chunk = packet[i : i + self.k]
            counter1 = self.hh1.update(chunk)

            if counter1 > 0:
                if s_temp == '':
                    s_temp = chunk
                    temp_counter = counter1
                else:
                    if counter1 > self.ratio * temp_counter:
                        s_temp += chunk[-1]
                        temp_counter = counter1
                    else:
                        if s_temp != '' and (s_temp not in local_signset):
                            counter2 = self.hh2.update(s_temp)
                            if deduplication:
                                local_signset.add(s_temp)
                            if counter2 > self.ratio * strings_counter:
                                signature_set.add(s_temp)
                                strings_counter = counter2
                        s_temp = chunk
                        temp_counter = counter1
            else:
                if s_temp != '' and (s_temp not in local_signset):
                    counter2 = self.hh2.update(s_temp)
                    if deduplication:
                        local_signset.add(s_temp)
                    if counter2 > self.ratio * strings_counter:
                        signature_set.add(s_temp)
                        strings_counter = counter2
                temp_counter = 0
                s_temp = ''

        if s_temp != '' and (s_temp not in local_signset):
            counter2 = self.hh2.update(s_temp)
            if counter2 > self.ratio * strings_counter:
                signature_set.add(s_temp)
                strings_counter = counter2
            
        if len(signature_set) != 0:
            tmp = set()
            for sign in signature_set:
                if sign in self.hh2.items.keys():
                    tmp.add(sign)
            a = '---'.join(sorted(list(tmp)))
            if len(a)!=0:
                self.hh3.update(a)
    
    def decode2(self):
        self.hh2.fixSubstringFrequency()
        return sorted(list(self.hh2.items.items()), key=lambda x: -x[1])


if __name__ == '__main__':
    print(DHH(packets=['httphttp'] * 30 + ['httpttp']*20, ratio=0.1, deduplication=True))