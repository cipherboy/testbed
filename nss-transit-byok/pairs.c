#include <assert.h>
#include <base64.h>

#include "algids.h"

CK_ULONG NTBFindPair(NTBValuePair_s *elements, size_t num_elems, const char *key) {
    if (key == NULL) {
        return 0;
    }

    for (size_t index = 0; index < num_elems; index++) {
        if (strcmp(key, elements[index].key) == 0) {
            return elements[index].value;
        }
    }

    return 0;
}

char *HexFormatByteBuffer(uint8_t *buffer, size_t length, size_t width) {
    width = (width == 0) ? 20 : width;
    width = (width > length) ? length : width;

    size_t output_offset = 0;
    size_t output_size = 7*length + 2*width;
    char *output = calloc(output_size, sizeof(char));

    size_t offset;
    for (offset = 0; offset < length && offset+width < length; offset += width) {
        output[output_offset] = '|';
        output_offset += 1;
        for (size_t charIndex = offset; charIndex < offset+width; charIndex++) {
            uint8_t value = buffer[charIndex];
            int ret = sprintf(output + output_offset, " %02x", value);
            assert(ret > 0);
            output_offset += (size_t)ret;
        }
        output[output_offset] = ' ';
        output_offset += 1;
        output[output_offset] = '|';
        output_offset += 1;
        output[output_offset] = ' ';
        output_offset += 1;
        for (size_t charIndex = offset; charIndex < offset+width; charIndex++) {
            uint8_t value = buffer[charIndex];
            if (value >= 32 && value < 126) {
                output[output_offset] = (char)value;
            } else {
                output[output_offset] = '.';
            }
            output_offset += 1;
        }
        output[output_offset] = '\n';
        output_offset += 1;
    }

    if (offset < length) {
        output[output_offset] = '|';
        output_offset += 1;

        for (size_t charIndex = offset; charIndex < length; charIndex++) {
            uint8_t value = buffer[charIndex];
            int ret = sprintf(output + output_offset, " %02x", value);
            assert(ret > 0);
            output_offset += (size_t)ret;
        }
        for (size_t charIndex = length - offset; charIndex < width; charIndex++) {
            output[output_offset] = ' ';
            output_offset += 1;
            output[output_offset] = ' ';
            output_offset += 1;
            output[output_offset] = ' ';
            output_offset += 1;
        }

        output[output_offset] = ' ';
        output_offset += 1;
        output[output_offset] = '|';
        output_offset += 1;
        output[output_offset] = ' ';
        output_offset += 1;

        for (size_t charIndex = offset; charIndex < length; charIndex++) {
            uint8_t value = buffer[charIndex];
            if (value >= 32 && value < 126) {
                output[output_offset] = (char)value;
            } else {
                output[output_offset] = '.';
            }
            output_offset += 1;
        }

        output[output_offset] = '\n';
        output_offset += 1;
    }

    output[output_offset] = 0;

    return output;
}

uint8_t *ReadFile(size_t *ret_size, const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file (%s) for reading\n", path);
        *ret_size = 0;
        return NULL;
    }

    *ret_size = 0;
    size_t buf_size = 72;
    uint8_t *ret_buffer = calloc(buf_size, sizeof(uint8_t));

    for (int filechar = fgetc(fp); filechar != EOF; filechar = fgetc(fp)) {
        if (*ret_size == buf_size) {
            // Expand our buffer
            buf_size = 2*buf_size;
            ret_buffer = realloc(ret_buffer, buf_size * sizeof(uint8_t));
            memset(ret_buffer + (*ret_size), 0, buf_size - (*ret_size));
        }
        ret_buffer[*ret_size] = (uint8_t)filechar;
        *ret_size += 1;
    }

    fclose(fp);
    return ret_buffer;
}

uint8_t *ParsePEM(size_t *base64_size, uint8_t **header, size_t *header_len, uint8_t *file_contents, size_t file_size) {
    *base64_size = 0;
    *header = NULL;
    *header_len = 0;

    if (file_size < 30) {
        fprintf(stderr, "Unexpectedly small file contents (%zu bytes)\n", file_size);
        return NULL;
    }

    size_t file_offset = 0;
    uint8_t filechar = file_contents[file_offset];

    size_t header_offset = 0;
    size_t header_size = 26;
    uint8_t *header_buffer = calloc(header_size, sizeof(uint8_t));

    filechar = file_contents[file_offset];
    while (file_offset < file_size && filechar != (uint8_t)'\n' && filechar != 0) {
        if (header_offset == header_size) {
            // Expand our buffer
            header_size = 2*header_size;
            header_buffer = realloc(header_buffer, header_size * sizeof(uint8_t));
            memset(header_buffer + header_offset, 0, header_size - header_offset);
        }

        header_buffer[header_offset] = filechar;
        header_offset += 1;

        file_offset += 1;
        filechar = file_contents[file_offset];
    }

    if (header_offset < 16) {
        fprintf(stderr, "Invalid PEM header; too small (%zu bytes):\n%s", header_offset, HexFormatByteBuffer(header_buffer, header_offset, 50));
        return NULL;
    }

    if (memcmp("-----BEGIN ", header_buffer, 11) != 0) {
        fprintf(stderr, "Invalid PEM header; expected starting with \"-----BEGIN \":\n%s", HexFormatByteBuffer(header_buffer, header_offset, 50));
        return NULL;
    }
    if (memcmp("-----", header_buffer + (header_offset - 5), 5) != 0) {
        fprintf(stderr, "Invalid PEM header; expected ending with \"-----\":\n%s", HexFormatByteBuffer(header_buffer, header_offset, 50));
        return NULL;
    }

    *header = header_buffer + 11;
    *header_len = header_offset - 11 - 5;

    size_t base64_offset = 0;
    size_t base64_length = 26;
    uint8_t *base64_buffer = calloc(base64_length, sizeof(uint8_t));

    if (file_offset >= file_size) {
        fprintf(stderr, "Invalid PEM: header too long: %zu bytes of %zu bytes total\n", file_offset, file_size);
        return NULL;
    }

    filechar = file_contents[file_offset];
    while (file_offset < file_size && filechar != 0 && filechar != '-') {
        if (base64_offset == base64_length) {
            // Expand our buffer
            base64_length = 2*base64_length;
            base64_buffer = realloc(base64_buffer, base64_length * sizeof(uint8_t));
            memset(base64_buffer + base64_offset, 0, base64_length - base64_offset);
        }

        base64_buffer[base64_offset] = filechar;
        base64_offset += 1;

        file_offset += 1;
        filechar = file_contents[file_offset];
    }

    if (base64_offset == base64_length) {
        // Expand our buffer
        base64_length = 2*base64_length;
        base64_buffer = realloc(base64_buffer, base64_length * sizeof(uint8_t));
        memset(base64_buffer + base64_offset, 0, base64_length - base64_offset);
    }
    base64_buffer[base64_offset] = 0;

    if (file_offset >= file_size) {
        fprintf(stderr, "Invalid PEM: base64 too long: %zu header, %zu bytes of Base64, and %zu bytes total\n", header_offset, file_offset-header_offset, file_size);
        return NULL;
    }

    size_t footer_offset = 0;
    size_t footer_size = 24;
    uint8_t *footer_buffer = calloc(footer_size, sizeof(uint8_t));

    filechar = file_contents[file_offset];
    while (file_offset < file_size && filechar != (uint8_t)'\n' && filechar != 0) {
        if (footer_offset == footer_size) {
            // Expand our buffer
            footer_size = 2*footer_size;
            footer_buffer = realloc(footer_buffer, footer_size * sizeof(uint8_t));
            memset(footer_buffer + footer_offset, 0, footer_size - footer_offset);
        }

        footer_buffer[footer_offset] = filechar;
        footer_offset += 1;

        file_offset += 1;
        filechar = file_contents[file_offset];
    }

    if (footer_offset < 16) {
        fprintf(stderr, "Invalid PEM footer; too small (%zu bytes):\n%s", footer_offset, HexFormatByteBuffer(footer_buffer, footer_offset, 50));
        return NULL;
    }

    if (memcmp("-----END ", footer_buffer, 9) != 0) {
        fprintf(stderr, "Invalid PEM footer; expected starting with \"-----END \":\n%s", HexFormatByteBuffer(footer_buffer, footer_offset, 50));
        return NULL;
    }
    if (memcmp("-----", footer_buffer + (footer_offset - 5), 5) != 0) {
        fprintf(stderr, "Invalid PEM footer; expected ending with \"-----\":\n%s", HexFormatByteBuffer(footer_buffer, footer_offset, 50));
        return NULL;
    }

    uint8_t *footer_type = footer_buffer + 9;
    size_t footer_len = footer_offset - 9 - 5;

    if (*header_len != footer_len) {
        fprintf(stderr, "Invalid PEM: mismatched header/footer types (%zu vs %zu bytes):\n%s\n%s", *header_len, footer_len, HexFormatByteBuffer(*header, *header_len, 50), HexFormatByteBuffer(footer_type, footer_len, 50));
    }
    if (memcmp(*header, footer_type, footer_len) != 0) {
        fprintf(stderr, "Invalid PEM: mismatched header/footer types:\n%s\n%s", HexFormatByteBuffer(header_buffer, header_offset, 50), HexFormatByteBuffer(footer_buffer, footer_offset, 50));
    }

    *base64_size = base64_offset;
    return base64_buffer;
}

uint8_t *ParsePEMKeyToDER(size_t *der_len, const char *path) {
    *der_len = 0;

    uint8_t *contents;
    size_t content_length;
    contents = ReadFile(&content_length, path);
    if (contents == NULL) {
        return NULL;
    }

    uint8_t *base64_content;
    size_t base64_len;
    uint8_t *header;
    size_t header_size;
    base64_content = ParsePEM(&base64_len, &header, &header_size, contents, content_length);
    if (base64_content == NULL) {
        fprintf(stderr, "Failed to parse %s as PEM\n", path);
        return NULL;
    }

    unsigned int derLen;
    uint8_t *der = ATOB_AsciiToData((char *)base64_content, &derLen);

    *der_len = (size_t)derLen;

    return der;
}
