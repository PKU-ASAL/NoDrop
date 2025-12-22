#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include "ioctl.h"

int main(int argc, char *argv[])
{
    int fd;
    int ret;
    FILE *file;
    struct buffer_count_info cinfo;
    struct fetch_buffer_struct fetch;
    struct nod_event_statistic nod_stat;
    struct stat lua_st;
    struct nod_lua_state lua_state;
    char lua_path[4096];
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [clean|fetch|stat|clear-stat|start|stop|count]\n", argv[0]);
        return 0;
    }

    fd = open(NOD_IOCTL_PATH, O_RDWR);
    if (fd < 0)
    {
        perror("Cannot open " NOD_IOCTL_PATH);
        return 127;
    }

    if (!strcmp(argv[1], "clean"))
    {
        if (!ioctl(fd, NOD_IOCTL_CLEAR_BUFFER, 0))
            fprintf(stderr, "Success\n");
    }
    else if (!strcmp(argv[1], "fetch"))
    {
        if ((ret = ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &cinfo)))
        {
            fprintf(stderr, "Get Buffer Count Info failed, reason %d\n", ret);
            return -1;
        }

        fetch.len = cinfo.unflushed_len;
        fetch.buf = malloc(fetch.len);
        if (!fetch.buf)
        {
            fprintf(stderr, "Allocate memory failed\n");
            return -1;
        }

        if ((ret = ioctl(fd, NOD_IOCTL_FETCH_BUFFER, &fetch)))
        {
            fprintf(stderr, "Fetch Buffer failed, reason %d\n", ret);
            return -1;
        }

        if (argc <= 2)
            file = stdout;
        else
            file = fopen(argv[2], "wb");
        if (!file)
        {
            fprintf(stderr, "Cannot open file\n");
            return -1;
        }

        if (fwrite(fetch.buf, fetch.len, 1, file) == 1)
        {
            fprintf(stderr, "Write %lu bytes to file %s\n", fetch.len, argc <= 2 ? "stdout" : argv[2]);
        }
        else
        {
            fprintf(stderr, "Write to file %s failed\n", argc <= 2 ? "stdout" : argv[2]);
        }

        if (file != stdout)
            fclose(file);
    }
    else if (!strcmp(argv[1], "count"))
    {
        if (!ioctl(fd, NOD_IOCTL_READ_BUFFER_COUNT_INFO, &cinfo))
        {
            printf("event_count=%lu,unflushed_count=%lu,unflushed_len=%lu\n", cinfo.event_count, cinfo.unflushed_count, cinfo.unflushed_len);
        }
    }
    else if (!strcmp(argv[1], "stat"))
    {
        if (!ioctl(fd, NOD_IOCTL_READ_STATISTICS, &nod_stat))
        {
            printf("n_evts\tdrop_evts\tdrop_unsolved\n%ld\t%ld\t%ld\n", nod_stat.n_evts, nod_stat.n_drop_evts, nod_stat.n_drop_evts_unsolved);
        }
    }
    else if (!strcmp(argv[1], "clear-stat"))
    {
        if (!ioctl(fd, NOD_IOCTL_CLEAR_STATISTICS, 0))
        {
            fprintf(stderr, "Statistics cleared\n");
        }
    }
    else if (!strcmp(argv[1], "stop"))
    {
        if (!ioctl(fd, NOD_IOCTL_STOP_RECORDING, 0))
            fprintf(stderr, "Stopped\n");
    }
    else if (!strcmp(argv[1], "start"))
    {
        if (argc <= 2)
        {
            fprintf(stderr, "Usage: %s start <lua_path>\n", argv[0]);
            return -1;
        }
        if (!realpath(argv[2], lua_path))
        {
            fprintf(stderr, "%s : lua path error\n", argv[2]);
            return -1;
        }
        if (strlen(lua_path) + 1 > 256)
        {
            fprintf(stderr, "%s : lua path too long\n", lua_path);
            return -1;
        }
        strcpy(lua_state.lua_path, lua_path);
        if (stat(lua_state.lua_path, &lua_st))
        {
            fprintf(stderr, "%s : lua file error\n", lua_path);
            return -1;
        }
        lua_state.lua_mtime = lua_st.st_mtime;
        if (!ioctl(fd, NOD_IOCTL_START_RECORDING, 0) && !ioctl(fd, NOD_IOCTL_SET_LUA_STATE, lua_state))
            fprintf(stderr, "Start: %s\n", lua_state.lua_path);
    }
    else
    {
        fprintf(stderr, "Unknown cmd %s\n", argv[1]);
    }

    return 0;
}
