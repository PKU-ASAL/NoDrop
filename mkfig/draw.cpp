#include <string>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <map>
#include <vector>
#include "../include/events.h"

#include "matplotlibcpp.h"

namespace plt = matplotlibcpp;

struct MyStruct {
    const char *filename;
    std::map<nanoseconds, uint32_t> *mp;
};

std::vector<std::string> files;

void * resolve_buf_file(void *arg) {
    uint64_t count;
    uint32_t total, pos;
    struct spr_event_hdr hdr;

    struct MyStruct *my_struct = (struct MyStruct *)arg;
    const char *filename = my_struct->filename;
    std::map<nanoseconds, uint32_t> *mp = my_struct->mp;


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
        if (hdr.magic != SPR_EVENT_HDR_MAGIC) {
            printf("%s: corrupted event %d: pos = 0x%x, magic = 0x%08x\n", filename, i, pos, hdr.magic);
            break;
        }

        ++mp->operator[](hdr.ts / 100000000);
        ++count;

        pos += hdr.len;
        if (pos + sizeof(int) >= total)   break;
        fseek(file, pos, SEEK_SET);
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

    std::vector<pthread_t> tids(files.size());
    std::vector<std::map<nanoseconds, uint32_t>> mps(files.size());
    std::vector<struct MyStruct> params(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        params[i] = {files[i].c_str(), &mps[i]};
        if (pthread_create(&tids[i], NULL, resolve_buf_file, (void*)&params[i])) {
            printf("%s: create pthread failed\n", files[i].c_str());
            i--;
        }
    }

    uint64_t total_count = 0;
    std::map<nanoseconds, uint32_t> evts;
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
        for (int i = 0; i < 100; ++i)
            y.emplace_back(evts[start + i + 10]);
        plt::figure_size(1200, 500);
        plt::xlabel("Time (100ms)");
        plt::ylabel("Events number");
        plt::ylim(0, int(*std::max_element(y.begin(), y.end()) * 1.1));

        plt::plot(y);
        plt::save(argv[2]);
    }

    return 0;
}
