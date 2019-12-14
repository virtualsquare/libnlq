#include <stdio.h>
#include <stdlib.h>
#include <libnlq.h>
int main(int argc, char *argv[]) {
	int rv = nlq_iplink_add(argv[2], atoi(argv[1]), "vde", NULL);
	if (rv < 0)
		perror("nlq_iplink_add");
	else
		printf("%d\n", rv);
}
