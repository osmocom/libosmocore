#include <osmocom/core/linuxlist.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/jhash.h>

struct item {
	const char blob[32];
	struct hlist_node node;
};

struct item items[] = {
	{ "blob one", },
	{ "blob two and five are the same", },
	{ "third blob", },
	{ "fourth blob", },
	{ "blob two and five are the same", },
};

uint32_t item_hash(const struct item *item)
{
	return osmo_jhash(item->blob, strlen(item->blob), 0);
}

int main(void)
{
	int i;
	struct item *item;

	DECLARE_HASHTABLE(haystack, 5);
	hash_init(haystack);

	printf("add:\n");
	for (i = 0; i < ARRAY_SIZE(items); i++) {
		uint32_t hash;
		item = &items[i];
		hash_add(haystack, &item->node, hash = item_hash(item));
		printf("- adding items[%d]#%x = %s\n", i, hash, item->blob);
	}

	printf("list:\n");
	hash_for_each (haystack, i, item, node)
		printf("- %s [%d]\n", item->blob, (int)(item - items));

	printf("find:\n");
	for (i = 0; i < ARRAY_SIZE(items); i++) {
		uint32_t hash;
		struct item *needle = &items[i];
		hash = item_hash(needle);
		printf("- looking up items[%d]#%x = %s\n", i, hash, needle->blob);
		hash_for_each_possible (haystack, item, node, hash)
			printf("  - %s items[%d]\n",
			       (item == needle) ? "found" : "not",
			       (int)(item - items));
	}

	return 0;
}
