/*
 * MIT License
 *
 * Copyright (c) 2020-2022 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <sys/stat.h>

#include <unistd.h>

char *link_string(char *s1, char *s2, int ispath)
{
    char *separator = "/";

    int length = ispath ? strlen(s1) + strlen(s2) + strlen(separator) + 1 : strlen(s1) + strlen(s2) + 1;
    int size = ispath ? sizeof(s1) + sizeof(s2) + sizeof(separator) + 1 : sizeof(s1) + sizeof(s2) + 1;
    char *new_str = (char *)calloc(length, size);

    strcat(new_str, s1);

    if (ispath)
      strcat(new_str, separator);

    strcat(new_str, s2);
    return new_str;
}

char *remove_last(char *str, int n)
{
    char *new_str = (char *) malloc(strlen(str));
    strcpy(new_str, str);
    new_str[strlen(new_str)-n] = '\0';
    return new_str;
}

void delete_file(char *path)
{
    int BUF_SIZE = 4096;
    struct stat path_buff;

    if (stat(path, &path_buff) == -1)
      return;

    off_t file_size = path_buff.st_size;
    int file = open(path, O_WRONLY);

    if (file == -1)
        return;

    void *buf = malloc(BUF_SIZE);
    memset(buf, 0, BUF_SIZE);

    ssize_t ret = 0;
    off_t shift = 0;

    while ((ret = write(file, buf, ((file_size - shift > BUF_SIZE) ? BUF_SIZE : (file_size - shift)))) > 0)
        shift += ret;

    close(file);
    free(buf);

    if (ret == -1)
        return;

    remove(path);
}
