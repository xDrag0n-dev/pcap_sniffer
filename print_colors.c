#include "print_colors.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

void	putchar_colored(char *color, char c);

int	printf_colored(char *color, char *format, ...)
{
	int	count = 0;
	va_list	args;
	va_start(args, format);

	while (*format) {
		if (*format == '%') {
			format++;
			switch (*format) {
				case 'd': /* decimal */
					int i = va_arg(args, int);
					count += printf("%d", i);
					break;
				case 'f': /* float or double */
					double d = va_arg(args, double);
					count += printf("%f", d);
					break;
				case 's': /* string */
					const char *s = va_arg(args, const char *);
					count += printf("%s", s);
					break;
				case 'u': /* unsigned */
					unsigned int ui = va_arg(args, int);
					count += printf("%u", ui);
					break;
				case 'c':
					char c = va_arg(args, int);
					count += printf("%c", c);
					break;
				case 'x': /* hexadecimal */
					unsigned char uc = va_arg(args, int);
					count += printf("%x", uc);
					break;
				case '%': /* % */
					count += printf("%%");
					break;
				default:
					count += printf("%%%c", *format);
					break;
			}
		}
		else {
			putchar_colored(color, *format);
			count++;
		}
		format++;
	}

	va_end(args);
	return (count);
}

void	putchar_colored(char *color, char c)
{
	printf("%s%1c", color, c);
	printf("%s", RESET);
}
