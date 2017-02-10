#include <stdio.h>

#include "detour.hpp"

typedef void (*main_t)();

void main_fn() {
	printf("Main!\n");
}

void hook_fn() {
	printf("Hooked main!\n");
}

int main(int argc, char **argv)
{
	main_fn();
	
	main_t main_bk = (main_t) detour((void *) main_fn, (void *) hook_fn);
	if (!main_bk) {
		printf("Failed to detour function...\n");
		return 0;
	}
	
	main_fn();
	main_bk();

	return 0;
}