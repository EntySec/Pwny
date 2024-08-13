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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifndef IS_WINDOWS
#include <termios.h>
#include <spawn.h>
#if defined(IS_IPHONE) || defined(IS_MACOS)
#include <util.h>
#else
#include <pty.h>
#endif
#endif

#include <ev.h>
#include <misc.h>
#include <log.h>
#include <queue.h>
#include <child.h>

#include <uthash/uthash.h>

#ifndef IS_IPHONE
#include <pawn.h>
#endif

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

void child_set_links(child_t *child,
                     link_t out_link,
                     link_t err_link,
                     link_t exit_link,
                     void *data)
{
    child->out_link = out_link;
    child->err_link = err_link;
    child->exit_link = exit_link;
    child->link_data = data != NULL ? data : child;
}

size_t child_read(child_t *child, void *buffer, size_t length)
{
    size_t bytes;

    if ((bytes = queue_remove(child->out_queue.queue, buffer, length)) < length)
    {
        bytes += queue_remove(child->err_queue.queue, buffer + bytes, length - bytes);
    }

    return bytes;
}

size_t child_write(child_t *child, void *buffer, size_t length)
{
    ssize_t count;
    ssize_t stat;

    for (count = 0; count < length; NULL)
    {
        do
        {
            stat = write(child->in, buffer + count, length - count);
        }
        while (stat == -1 && errno == EINTR);

        if (stat < 0)
        {
            break;
        }

        log_debug("* Writing bytes to child (%d)\n", stat);
        count += stat;
    }

    return count > 0 ? count : -1;
}

void child_out(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;
    int length;

    child = w->data;
    log_debug("* Child read out event initialized (%d)\n", w->fd);

    while ((length = queue_from_fd(child->out_queue.queue, w->fd)) > 0)
    {
        log_debug("* Child read from out (%d)\n", length);

        if (child->out_link)
        {
            child->out_link(child->link_data);
        }
    }
}

void child_err(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;
    int length;

    child = w->data;
    log_debug("* Child read err event initialized (%d)\n", w->fd);

    while ((length = queue_from_fd(child->err_queue.queue, w->fd)) > 0)
    {
        log_debug("* Child read from err (%d)\n", length);

        if (child->err_link)
        {
            child->err_link(child->link_data);
        }
    }
}

void child_exit(struct ev_loop *loop, struct ev_child *w, int revents)
{
    child_t *child;

    child = w->data;
    log_debug("* Child exit event initialized\n");

    child->status = CHILD_DEAD;

    if (child->exit_link)
    {
        child->exit_link(child->link_data);
    }

    ev_child_stop(loop, w);
    ev_io_stop(child->loop, &child->out_queue.io);
    ev_io_stop(child->loop, &child->err_queue.io);
}

static void child_from_image(child_t *child, unsigned char *image,
                             char **argv, char **env, child_options_t *options)
{
    ev_loop_fork(EV_DEFAULT);
    ev_loop_destroy(EV_DEFAULT_UC);

#if IS_LINUX
    pawn_exec(image, argv, NULL);
#elif IS_WINDOWS
    pawn_exec(image, argv);
#elif IS_MACOS
    pawn_exec_bundle(image, options->length, argv, env);
#endif

    abort();
}

static void child_from_file(child_t *child, char *filename,
                            char **argv, char **env, child_options_t *options)
{
    ev_loop_fork(EV_DEFAULT);
    ev_loop_destroy(EV_DEFAULT_UC);

    execve(filename, argv, env);

    abort();
}

static pid_t child_spawn(char *filename, unsigned char *image,
                         child_options_t *options,
                         child_pipes_t *pipes)
{
#ifndef IS_WINDOWS
    pid_t pid;
    int posix_stat;

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;

    if (filename == NULL)
    {
        log_debug("* Image loading is not supported with posix_spawn()\n");
        return -1;
    }

    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);

    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipes->out_pair[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipes->in_pair[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipes->err_pair[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipes->out_pair[1]);
    posix_spawn_file_actions_addclose(&actions, pipes->in_pair[0]);
    posix_spawn_file_actions_addclose(&actions, pipes->err_pair[1]);

    if ((posix_stat = posix_spawn(&pid, filename, &actions, &attr, options->argv, options->env)) != 0)
    {
        log_debug("* posix_spawn() failed with status (%d)\n", posix_stat);

        posix_spawn_file_actions_destroy(&actions);
        posix_spawnattr_destroy(&attr);

        return -1;
    }

    log_debug("* posix_spawn() succeeded on (%s)\n", filename);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);

    return pid;
#endif

    log_debug("* posix_spawn() is not supported on Windows\n");
    return -1;
}

static pid_t child_fork(child_t *child, char *filename, unsigned char *image,
                        child_options_t *options,
                        child_pipes_t *pipes)
{
    pid_t pid;
    int master;
    struct termios tios;

    if (options->flags & CHILD_FAKE_PTY)
    {
        log_debug("* Initializing fake PTY\n");
        pid = forkpty(&master, NULL, NULL, NULL);

        if (pid == 0)
        {
            tcgetattr(master, &tios);
            tcsetattr(master, TCSADRAIN, &tios);
        }

	    log_debug("* PID: %d, FD: %d\n", pid, master);

        pipes->in_pair[0] = master;
        pipes->in_pair[1] = master;
        pipes->out_pair[0] = master;
        pipes->out_pair[1] = master;
        pipes->err_pair[0] = master;
        pipes->err_pair[1] = master;
    }
    else
    {
        pid = fork();
    }

    if (pid == 0)
    {
        /*int ttyfd = open("/dev/tty", O_RDWR);
        close(ttyfd);*/
        /* workaround for macOS */

        dup2(pipes->in_pair[0], STDIN_FILENO);
        dup2(pipes->out_pair[1], STDOUT_FILENO);
        dup2(pipes->err_pair[1], STDERR_FILENO);

        if (image != NULL)
        {
            child_from_image(child, image, options->argv, options->env, options);
        }
        else if (filename != NULL)
        {
            child_from_file(child, filename, options->argv, options->env, options);
        }

        return 0;
    }
    else if (pid == -1)
    {
        return -1;
    }

    return pid;
}

child_t *child_create(char *filename, unsigned char *image, child_options_t *options)
{
    child_t *child;
    child_pipes_t pipes;

    size_t argc;
    char *args;

    argc = 0;
    options->argv = NULL;

    if (options->args)
    {
        if (filename != NULL)
        {
            asprintf(&args, "%s %s", filename, options->args);
        }
        else
        {
            asprintf(&args, "pwny %s", options->args);
        }

        options->argv = misc_argv_split(args, options->argv, &argc);
    }

    if (options->argv == NULL)
    {
        options->argv = realloc(options->argv, sizeof(char *) * 2);
        options->argv[0] = filename != NULL ? filename : "pwny";
        options->argv[1] = NULL;
    }

    for (int i = 0; i < argc; i++)
    {
        log_debug("* %d: %s\n", i, options->argv[i]);
    }

    if (pipe(pipes.err_pair) == -1)
    {
        log_debug("* Failed to create err pair for child\n");
        goto fail;
    }

    if (pipe(pipes.in_pair) == -1)
    {
        log_debug("* Failed to create in pair for child\n");
        goto fail;
    }

    if (pipe(pipes.out_pair) == -1)
    {
        log_debug("* Failed to create out pair for child\n");
        goto fail;
    }

    child = calloc(1, sizeof(*child));

    if (child == NULL)
    {
        goto fail;
    }

    if (options->flags & CHILD_NO_FORK)
    {
        child->pid = child_spawn(filename, image, options, &pipes);
    }
    else
    {
        child->pid = child_fork(child, filename, image, options, &pipes);
    }

    free(options->argv);

    if (child->pid == -1)
    {
        free(child);
        return NULL;
    }

    child->child.data = child;
    child->loop = ev_default_loop(CHILD_EV_FLAGS);

    ev_child_init(&child->child, child_exit, child->pid, 0);
    ev_child_start(child->loop, &child->child);

    fcntl(pipes.in_pair[1], F_SETFL, O_NONBLOCK);
    child->in = pipes.in_pair[1];

    fcntl(pipes.out_pair[0], F_SETFL, O_NONBLOCK);

    child->out = pipes.out_pair[0];
    child->out_queue.io.data = child;
    child->out_queue.queue = queue_create();

    ev_io_init(&child->out_queue.io, child_out, child->out, EV_READ);
    ev_io_start(child->loop, &child->out_queue.io);

    fcntl(pipes.err_pair[0], F_SETFL, O_NONBLOCK);

    child->err = pipes.err_pair[0];
    child->err_queue.io.data = child;
    child->err_queue.queue = queue_create();

    ev_io_init(&child->err_queue.io, child_err, child->err, EV_READ);
    ev_io_start(child->loop, &child->err_queue.io);

    close(pipes.in_pair[0]);
    close(pipes.out_pair[1]);
    close(pipes.err_pair[1]);

    child->status = CHILD_ALIVE;

    return child;

fail:
    free(options->argv);
    return NULL;
}

void child_kill(child_t *child)
{
    kill(child->pid, SIGINT);
}

void child_destroy(child_t *child)
{
    close(child->in);
    close(child->out);
    close(child->err);

    queue_free(child->out_queue.queue);
    queue_free(child->err_queue.queue);

    free(child);
}
