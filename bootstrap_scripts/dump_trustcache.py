import struct
import sys

fd = open(sys.argv[1], "rb")
data = fd.read()
fd.close()

'''
struct trust_cache_entry1 {
	uint8_t cdhash[CS_CDHASH_LEN];//20
	uint8_t hash_type;
	uint8_t flags;
} __attribute__((__packed__));

struct trust_cache_module1 {
	uint32_t version;
	uuid_t uuid;
	uint32_t num_entries;
	struct trust_cache_entry1 entries[];
} __attribute__((__packed__));
'''
print("version:", struct.unpack("<I",data[0:4])[0])
print("uuid:", data[4:20].hex())

num_entries = struct.unpack("<I", data[20:24])[0]

print("num_entries:", num_entries)
data = data[24:]
for i in range(num_entries):
    print(F"entry {i}:")
    cdhash = data[:20]
    hash_type = struct.unpack("B", data[20:21])[0]
    flags = struct.unpack("B", data[21:22])[0]
    print("\tcdhash:", cdhash.hex())
    print("\thash_type:", hash_type)
    print("\tflags:", flags)
    data = data[22:]
    # if len(data) <=0:
    #     break


