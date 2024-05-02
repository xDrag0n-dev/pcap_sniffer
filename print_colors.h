#ifndef	H_PRINT_COLORS
#define	H_PRINT_COLORS

#define	RESET	"\033[0m"
#define	RED	"\033[31m"
#define	GREEN	"\033[32m"
#define	YELLOW	"\033[33m"
#define	BLUE	"\033[34m"
#define	MAGENTA	"\033[35m"
#define	CYAN	"\033[36m"
#define	WHITE	"\033[37m"

int	printf_colored(char *color, char *msg, ...);
void	putchar_colored(char *color, char c);

#endif
