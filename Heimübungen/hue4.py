p, g = 541, 15

def get_tag(x):
    return g ** x % p

def get_all_x(tag):
    l = []
    for x in range(541):
        if get_tag(x) == tag:
            l += [x]
    return l

# contains all possible x for all tags in [0-540]
all_x_of_tags = [[]]
overall_len = 0
for tag in range(541):
    l = get_all_x(tag)
    all_x_of_tags += [l]
    overall_len += len(l)

print(overall_len)