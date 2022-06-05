#include <string>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <map>
#include <vector>
#include <inttypes.h>

#include "events.h"
#include "matplotlibcpp.h"

/* Install dependency: 
 * apt-get install python3-matplotlib python3-numpy python3-dev
 */

namespace plt = matplotlibcpp;

#define GRAINED 50
#define DURATION 30
#define STR_HELPER(x) #x 
#define STR(x) STR_HELPER(x)

struct MyStruct {
    const char *filename;
    std::map<nanoseconds, uint32_t> *mp;
    std::vector<uint32_t> *attackers;
};

std::vector<std::string> files;
std::vector<pthread_t> tids;
std::vector<std::map<nanoseconds, uint32_t>> mps;
std::vector<struct MyStruct> params;
std::vector<std::vector<uint32_t>> attacker;

static int _parse(struct nod_event_hdr *hdr, char *buffer, void *__data)
{
    size_t i;
    const struct nod_event_info *info;
    const struct nod_param_info *param;
    uint16_t *args;
    char *data;

    // std::vector<uint32_t> *attackers = (std::vector<uint32_t> *)__data;

    if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
        return -1;

    info = &g_event_info[hdr->type];
    args = (uint16_t *)buffer;
    data = (char *)(args + info->nparams);

    // if (std::count(attackers->begin(), attackers->end(), hdr->tid)) {
    //     ;
    // } else if (hdr->type == NODE_SYSCALL_EXECVE) {
    //     char tmp = *(data + args[0] + args[1] + args[2]);
    //     *(data + args[0] + args[1] + args[2]) = 0;
    //     if (strstr(data + args[0] + args[1], "attacker")) {
    //         *(data + args[0] + args[1] + args[2]) = tmp;
    //         attackers->push_back(*(uint32_t *)(data + args[0] + args[1] + args[2] + args[3]));
    //     } else {
    //         *(data + args[0] + args[1] + args[2]) = tmp;
    //         return -1;
    //     }
    // } else {
    //     return -1;
    // }
    
    printf("%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);

    for (i = 0; i < info->nparams; ++i) {
        param = &info->params[i];
        if (i > 0)  printf(", ");
        printf("%s=", param->name);
        switch(param->type) {
        case PT_CHARBUF:
        case PT_FSPATH:
        case PT_FSRELPATH:
        case PT_BYTEBUF:
            fwrite(data, args[i], 1, stdout);
            break;

        case PT_FLAGS8:
        case PT_UINT8:
        case PT_SIGTYPE:
            printf("%" PRIu8, *(uint8_t *)data);
            break;
        case PT_FLAGS16:
        case PT_UINT16:
        case PT_SYSCALLID:
            printf("%" PRIu16, *(uint16_t *)data);
            break;
        
        case PT_FLAGS32:
        case PT_UINT32:
        case PT_MODE:
        case PT_UID:
        case PT_GID:
        case PT_SIGSET:
            printf("%" PRIu32, *(uint32_t *)data);
            break;
        
        case PT_RELTIME:
        case PT_ABSTIME:
        case PT_UINT64:
            printf("%" PRIu64, *(uint64_t *)data);
            break;

        case PT_INT8:
            printf("%" PRId8, *(int8_t *)data);
            break;

        case PT_INT16:
            printf("%" PRId16, *(int16_t *)data);
            break;
        
        case PT_INT32:
            printf("%" PRId32, *(int32_t *)data);
            break;

        case PT_INT64:
        case PT_ERRNO:
        case PT_FD:
        case PT_PID:
            printf("%" PRId64, *(int64_t *)data);
            break;

        default:
            printf("<unknown>");
            break;
        }

        data += args[i];
    }
    printf(")\n");
    return 0;
}

void * resolve_buf_file(void *arg) {
    uint64_t count;
    uint32_t total, pos;
    struct nod_event_hdr hdr;
    char *buffer;


    struct MyStruct *my_struct = (struct MyStruct *)arg;
    const char *filename = my_struct->filename;
    std::map<nanoseconds, uint32_t> *mp = my_struct->mp;
    std::vector<uint32_t> *attackers = my_struct->attackers;


    FILE *file = fopen(filename, "rb+");
    if (!file) {
        printf("%s: open failed\n", filename);
        return (void *)0;
    }

    pos = 0;
    count = 0;
    mp->clear();

    fseek(file, 0, SEEK_END);
    total = ftell(file);
    fseek(file, 0, SEEK_SET);

    for (int i = 0; ; ++i) {
        if(fread(&hdr, sizeof(hdr), 1, file) != 1) {
            printf("%s: read %d event header failed (pos = 0x%x)\n", filename, i, pos);
            break;
        }
        if (hdr.magic != NOD_EVENT_HDR_MAGIC) {
            printf("%s: corrupted event %d: pos = 0x%x, magic = 0x%08x\n", filename, i, pos, hdr.magic);
            break;
        }


        buffer = (char *)malloc(hdr.len - sizeof(struct nod_event_hdr));
        if (buffer) {
            if (fread(buffer, hdr.len - sizeof(struct nod_event_hdr), 1, file) != 1) {
                free(buffer);
                break;
            }
            
            if (!_parse(&hdr, buffer, attackers)) {
                ++mp->operator[](hdr.ts / (1000000 * GRAINED));
                ++count;
            }
            free(buffer);
            pos += hdr.len;
        } else {
            pos += hdr.len;
            fseek(file, pos, SEEK_SET);
        }

        if (pos >= total)   break;
    }

    fclose(file);
    printf("%s: done (%lu records)\n", filename, count);
    return (void *)count;
}

void traverse_dir(const char *dirname) {
    struct stat s;
    struct dirent *filename;
    DIR *dir;

    lstat(dirname, &s);
    if (!S_ISDIR(s.st_mode)) {
        printf("%s is not a directory\n", dirname);
        return;
    }

    dir = opendir(dirname);
    if (dir == NULL) {
        printf("cannot open %s\n", dirname);
        return;
    }

    while ((filename = readdir(dir)) != NULL) {
        if (strstr(filename->d_name, ".buf"))
            files.emplace_back(std::string(dirname) + "/" + std::string(filename->d_name));
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        traverse_dir(argv[1]);
    } else {
        traverse_dir("/tmp/pinject");
    }

    tids.resize(files.size());
    mps.resize(files.size());
    params.resize(files.size());
    attacker.resize(files.size());

    for (size_t i = 0; i < files.size(); ++i) {
        params[i] = {files[i].c_str(), &mps[i]};
        params[i].attackers = &attacker[i];
        if (pthread_create(&tids[i], NULL, resolve_buf_file, (void*)&params[i])) {
            printf("%s: create pthread failed\n", files[i].c_str());
            i--;
        }
    }

    uint64_t total_count = 0;
    std::map<nanoseconds, uint32_t> evts;
    // std::vector<uint32_t> total_attacker;
    // for (size_t i = 0; i < tids.size(); ++i) {
    //     uint32_t tmp_count;
    //     pthread_join(tids[i], (void **)&tmp_count);

    //     for (auto pid : attacker[i]) {
    //         if (!std::count(total_attacker.begin(), total_attacker.end(), pid))
    //             total_attacker.push_back(pid);
    //     }

    //     params[i].attackers = &total_attacker;
    //     if (pthread_create(&tids[i], NULL, resolve_buf_file, (void*)&params[i])) {
    //         printf("%s: create pthread failed\n", files[i].c_str());
    //     }
    // }

    for (size_t i = 0; i < tids.size(); ++i) {
        uint32_t tmp_count;
        pthread_join(tids[i], (void **)&tmp_count);
        total_count += tmp_count;
        for (auto &it : mps[i]) {
            evts[it.first] += it.second;
        }
    }

    printf("total_count = %lu\n", total_count);

    if (argc > 2) {
        nanoseconds start = evts.begin()->first;
        std::vector<nanoseconds> y;
        for (int i = 0; i < ((1000 * DURATION) / GRAINED); ++i)
            y.emplace_back(evts[start + i]);
        plt::figure_size(1200, 500);
        plt::xlabel("Time (" STR(GRAINED) "ms)");
        plt::ylabel("Events number");
        plt::ylim(0, int(*std::max_element(y.begin(), y.end()) * 1.1));

        plt::plot(y);
        plt::save(argv[2]);
    }

    return 0;
}
