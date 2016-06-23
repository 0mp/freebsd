#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BSMCONV_BUFFER_SIZE 64
#define	BSMCONV_REALLOC_MODIFIER 4

enum bsmconv_scanner_state {
	BSMCONV_AWAITING_ANOTHER_EVENT,
	BSMCONV_SCANNING_FOR_ANOTHER_MSG
};

static void
append_buffer(char ** out_bufferp, const char * const in_buffer,
    size_t * const out_buffer_lenp, size_t * const out_buffer_sizep,
    const size_t in_buffer_len)
{
	size_t new_len;
	size_t new_size;

	new_len = *out_buffer_lenp + in_buffer_len;
	new_size = *out_buffer_sizep;

	if (new_len > *out_buffer_sizep) {
		new_size = *out_buffer_sizep;
		while (new_size < new_len)
			new_size *= BSMCONV_REALLOC_MODIFIER;
		*out_bufferp = realloc(*out_bufferp, new_size);
		if (*out_bufferp == NULL)
			err(errno, "realloc");
	}

	memcpy(*out_bufferp + *out_buffer_lenp, in_buffer, in_buffer_len);
	*out_buffer_lenp = new_len;
	*out_buffer_sizep = new_size;
	warnx("New length: %zu, new size: %zu", new_len, new_size);
}

int main()
{
	char *parsing_buffer;
	char reading_buffer[BSMCONV_BUFFER_SIZE];
	enum bsmconv_scanner_state scanner_state;
	ssize_t bytes_read;
	size_t parsing_buffer_len;
	size_t parsing_buffer_size;
	size_t processed_bytes;

	parsing_buffer_len = 0;
	parsing_buffer_size = BSMCONV_BUFFER_SIZE;
	parsing_buffer = malloc(sizeof(char) * parsing_buffer_size);
	if (parsing_buffer == NULL)
		err(errno, "malloc");

	scanner_state = BSMCONV_AWAITING_ANOTHER_EVENT;
	processed_bytes = 0;

	while ((bytes_read = read(STDIN_FILENO, reading_buffer,
	    BSMCONV_BUFFER_SIZE)) > 0) {
		append_buffer(&parsing_buffer, reading_buffer,
		    &parsing_buffer_len, &parsing_buffer_size, bytes_read);
		// Find msg.
		// Wait for another msg.
		// Compare.
		// Continue getting the whole event or start parsing the event.
	}

	if (bytes_read == -1)
		err(errno, "read");

	/* else if (bytes_read == 0) */
	/*         warn("End of file."); */

	free(parsing_buffer);

	return 0;
}
