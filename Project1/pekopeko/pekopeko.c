#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <seccomp.h>
#include <linux/seccomp.h>

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	return;
}

void init_seccomp()
{
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	seccomp_load(ctx);
}

void banner()
{
	puts("⡟⢹⣿⡿⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⣿⣿⠉⠛⣿⣿⣿⣿⠋⠉⠉⡟⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⡟⠉⠉⣻⣿⣿⣿⣿⠛⡛⠉⠉⣿⣿⠋⠉⠉⠉⠉⠉⠉⠉⠉⢻");
	puts("⣷⣾⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣀⠛⠁⠀⢹⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠀⠀⢠⣿⣿⣿⠟⢁⣼⣤⣤⣼⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⣗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠶⠛⠉⢩⡀⡠⠀⣼⠇⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⡀⢀⠇⠀⢀⣾⣿⡿⠁⣠⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠤⠚⠉⠀⠀⠀⠀⢹⡿⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⢀⠌⠛⢫⡤⠞⢿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠊⠁⠀⠀⠀⠀⠀⢀⡴⠊⠀⠀⡠⠊⠀⠀⢀⠔⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠈⠀⢀⠀⠃⠀⠀⠈⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⢀⡾⠀⠀⠀⠀⠁⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⡄⢀⣴⠋⠀⠀⠀⠀⠀⠀⢀⣴⡿⠄⠀⢀⣠⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠠⡀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣄⠀⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣥⠖⠀⠀⠀⣀⣀⣤⣿⣿⣱⠁⢀⣾⣟⣠⣄⣞⡄⠀⠀⠀⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠐⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡄⢸");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣷⣶⣿⠿⢿⣿⣿⣿⣿⣿⡀⣼⣿⣿⣿⣿⡟⠀⠀⠀⢠⡦⠀⣼⣇⠀⠘⣆⠀⠀⠀⠀⠀⠀⠈⣧⠀⠀⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣷⣾");
	puts("⡇⠀⠀⣠⣴⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⣸⠃⢀⣿⣿⡇⠀⣿⡀⠀⠀⠀⡀⠀⣆⠸⡆⠀⣸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿");
	puts("⡇⢀⣜⣵⡿⠟⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠳⠀⠙⢸⡏⠐⣾⡏⣿⣧⠀⢸⣇⣄⠀⠀⢳⠀⢻⠠⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿");
	puts("⣧⡜⣴⠏⠀⢸⣿⣿⠿⠛⠛⠉⠉⠁⠀⠀⢰⣿⣿⣿⢻⣿⣿⣿⣿⠟⠛⢡⡿⠁⢠⠂⢲⡟⠒⣤⠏⠀⣿⣿⠀⠈⣿⠹⣧⠀⢸⣆⣸⣾⣿⣿⠟⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻");
	puts("⣿⣿⠃⠀⠀⣿⣿⣿⣿⣶⣦⣴⣴⣶⣤⣶⣾⠃⢸⣿⠈⣿⢹⡟⡟⠀⠀⣸⢃⡠⠁⢠⡟⢀⣰⣿⡇⠀⢿⢻⠀⠀⢸⡄⣷⠀⠐⣿⢿⣿⣿⣿⠀⢘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⠃⠀⠀⢠⣿⣿⣿⣿⣿⣿⡿⠿⠿⠟⠻⣿⠀⣿⡇⢠⡏⢸⣇⡇⠀⠀⣿⣿⠃⣠⠟⢠⣾⠟⠉⠀⠀⢸⣼⡇⠀⠸⣇⢸⠀⠀⣸⠈⣿⣿⣿⣴⣿⣿⠀⠀⠀⢠⣴⡀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣤⣠⢀⡾⠁⠹⣿⣿⣿⣿⣿⣿⣷⣶⣼⡇⢸⣿⡅⢸⠃⢸⣿⠇⠀⠀⣿⣥⣾⣯⡼⠋⠁⠀⠀⠀⠀⠸⡟⢷⠀⠀⢻⡮⠄⠀⣹⠀⡟⣿⣿⣿⣿⣿⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⡿⣣⡾⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⡇⣾⣿⡇⣾⠀⠈⣿⡇⠀⠠⡟⠋⠉⠋⠒⠢⢤⡀⠀⠀⠀⠀⣷⠸⡇⠀⠈⣇⡇⠀⢸⠀⣇⡏⣿⣿⣿⢿⠷⡦⣼⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣾⣿⠷⣶⣶⠦⠬⢿⣿⣿⣿⣿⣮⡛⢿⡇⣛⣙⣃⡿⠀⠀⢿⣿⣆⠀⣷⣶⠾⠿⢿⣶⣦⡁⠀⠀⠀⠀⠘⠀⢿⠀⠀⢹⣷⠀⢻⢸⣿⡇⣿⠈⠉⢸⡄⠀⠀⠹⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣉⣤⣶⡿⡟⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⡇⠀⢀⣬⣿⠻⣆⠘⢂⠀⠀⠀⠀⠉⠃⠀⠀⠀⠀⠀⠀⠘⠃⠶⠦⢽⠄⡌⢸⡿⢠⡏⠀⠀⣸⠀⠀⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⡿⠛⠉⣰⠁⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⢸⣽⠀⣹⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠾⢷⣦⣄⠀⠃⣸⠇⣼⠇⠀⠀⣿⠀⠀⠀⠀⢸⣄⠀⠀⠀⠀⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠸⡏⠀⠻⢿⡿⠗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣦⢠⡟⢠⡟⠀⠀⠀⣿⠀⠀⠀⠀⢸⡏⠛⠳⢤⡀⠀⠀⠀⠀⢸");
	puts("⡿⠛⠉⠀⠀⠀⠀⠀⠀⢠⣶⡄⠈⢿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡄⠀⢙⡿⣠⣿⡇⠀⠀⣰⣿⠀⠀⠀⠀⢸⣿⠀⠀⠀⠉⠲⣶⣶⣤⣼");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⠀⠀⠻⣿⣿⣿⣿⣿⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣦⣂⠀⠀⠀⠀⠀⠀⣿⡷⢀⣾⣿⡿⣳⠀⠀⡇⣿⣿⡄⠀⠀⠀⣿⣿⡀⠀⠀⠀⠀⠘⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣧⣤⣤⣿⣿⣿⣿⣿⢠⠠⢴⢺⣆⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣷⣿⠆⠀⠀⠈⠀⣸⣿⠟⡇⠋⠀⢸⢱⠙⠻⢷⣄⣠⣾⣿⣿⡇⢰⡀⠀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣾⣿⣷⣄⠀⠀⠀⠀⠀⠀⠈⠛⠿⢿⡿⠿⠋⠀⠀⠀⠀⢰⣿⡄⢠⠀⠀⠀⣿⡎⠀⢀⣴⣿⣿⣿⣿⣿⡇⢸⣇⠀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠁⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣿⣿⠇⣜⡄⠀⢀⣿⣇⣴⣿⣿⣿⣿⣿⣿⣿⠇⢸⣿⡀⠀⠀⣿⣿⣿");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢉⡿⠟⠉⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⢀⣀⣤⣴⠚⠛⠋⠉⠀⠀⣿⣷⣴⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢰⣼⣿⣷⣾⣿⡿⠟⢻");
	puts("⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡖⠉⠀⠀⠀⠀⠀⠀⢻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣷⠶⠞⠋⠉⠀⠀⠀⠓⢤⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⢸");
	puts("⡇⠀⣠⣦⠀⠀⠀⠀⠀⢠⡎⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠈⣿⡏⢉⠽⠟⠛⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⡀⠀⢸⣿⣿⣿⣿⢿⣿⣿⣿⠿⢿⣿⣿⡿⢿⣿⣿⣿⣿⡿⠁⠙⢄⢸");
	puts("⡇⢰⣿⣿⠀⠀⠀⠀⢰⡯⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⠀⣾⣿⣿⣿⡇⠸⢿⣿⡄⠀⣼⣿⣻⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⢿");
	puts("⣷⣾⣿⠏⠀⠀⠀⠀⡼⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⣿⣿⣿⣿⠀⠁⠘⣿⣧⣴⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⢸");
	puts("⣿⣿⣿⣷⡀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⣠⡶⠋⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡇⡘⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⣸");
	puts("⣿⣿⣿⡿⠃⠀⣠⠔⠻⣷⣄⡀⠀⠀⠀⠀⢰⡿⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠻⣼⠱⠁⠘⠿⣿⣿⣿⡟⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⣿");
	puts("⡿⠋⠉⠀⢀⡞⠁⠀⠀⠈⠉⠙⠲⠶⣄⣀⣿⡇⠀⠀⠀⠀⢃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠀⠀⡿⠁⠀⠀⠀⠀⠉⠹⡇⠉⠻⣿⣿⣿⠃⠀⠀⠀⠀⡀⠀⢸");
	puts("⡇⠀⠀⠀⡞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⡏⠀⠀⠀⠀⠀⠀⠀⠤⣀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⣀⣠⣤⠖⠋⢸⣿⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀⠙⠀⠀⠸⢿⣿⡆⠀⠀⠀⣴⣿⣄⣸");
	puts("⣧⣀⣀⣼⣄⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣸⣤⣤⣀⣀⣀⣼⣀⣀⣁⣀⣀⣀⣠⣤⣤⣶⣶⣶⣿⣟⣉⣉⣁⣀⣀⣀⣼⣿⣤⣦⣼⣦⣀⣀⣀⣀⣀⣀⣀⣀⣴⣥⣤⣭⣷⣤⣤⣾⣿⣿⣿⣿");
}

int main()
{
	init();
	banner();
	char ans[4], squeak[] = "pekopekopekopekopekopekopekopekopekopekopekopekopekopekopekopeko";

	puts("I think pekora is the best VTuber. Isn't it?");
	scanf("%3s", ans);

	if (strncmp(ans, "yes", 3))
	{
		puts("poor guy....");
		exit(0);
	}
	else
		puts("You will pass the course.");

	init_seccomp();

	read(0, squeak, 64);

	int i;

	for (i = 0; i < 64; i++)
	{
		if (i % 11 == 5 && squeak[i] != '\x87')
		{
			exit(0);
		}
	}

	void (*func)() = (void (*)())squeak;
	(*func)();

	return 0;
}