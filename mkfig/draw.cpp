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

std::string output_name = "data.png";
std::string search_path = ".";
std::vector<std::string> files;

void * resolve_buf_file(void *arg) {
    int total;
    uint32_t count;
    uint32_t pos;
    struct MyStruct *my_struct = (struct MyStruct *)arg;
    std::string filename_str = search_path + "/" + std::string(my_struct->filename);
    const char *filename = filename_str.c_str();

    std::map<nanoseconds, uint32_t> *mp = my_struct->mp;

    struct spr_event_hdr hdr;

    FILE *file = fopen(filename, "rb+");
    if (!file) {
        printf("%s: open failed\n", filename);
        return (void *)0;
    }

    fseek(file, -4, SEEK_END);
    fread(&total, 4, 1, file);
    fseek(file, 0, SEEK_SET);

    pos = 0;
    count = 0;
    mp->clear();
    printf("%s: %d expected records\n", filename, total);
    for (int i = 0; i < total; ++i) {
        if(fread(&hdr, sizeof(hdr), 1, file) != 1) {
            printf("%s: read failed\n", filename);
            break;
        }
        if (hdr.magic != SPR_EVENT_HDR_MAGIC) {
            printf("%s: corrupted magoc %d %x %x\n", filename, i, pos, hdr.magic);
            break;
        }
        ++mp->operator[](hdr.ts / 100000000);
        ++count;

        fseek(file, hdr.len - sizeof(hdr), SEEK_CUR);
        pos += hdr.len;
    }

    fclose(file);
    printf("%s: done\n", filename);
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
        if (!strcmp(filename->d_name, ".") || !strcmp(filename->d_name, ".."))
            continue;
        if (strstr(filename->d_name, ".buf"))
            files.emplace_back(std::string(filename->d_name));
    }
}

int main(int argc, char *argv[]) {

    if (argc > 1) {
        search_path = std::string(argv[1]);
    }
    traverse_dir(search_path.c_str());

    std::vector<pthread_t> tids(files.size());
    std::vector<std::map<nanoseconds, uint32_t>> mps(files.size());
    std::vector<struct MyStruct> params(files.size());
    for (int i = 0; i < files.size(); ++i) {
        params[i] = {files[i].c_str(), &mps[i]};
        if (pthread_create(&tids[i], NULL, resolve_buf_file, (void*)&params[i])) {
            printf("%s: create pthread failed\n", files[i].c_str());
            i--;
        }
    }

    uint32_t total_count = 0;
    std::map<nanoseconds, uint32_t> evts;
    for (int i = 0; i < tids.size(); ++i) {
        uint32_t tmp_count;
        pthread_join(tids[i], (void **)&tmp_count);
        total_count += tmp_count;
        for (auto &it : mps[i]) {
            evts[it.first] += it.second;
        }
    }

    printf("total_count = %u\n", total_count);
    std::vector<nanoseconds> idx;
    nanoseconds start = evts.begin()->first;
    std::vector<nanoseconds> y;
    for (int i = 0; i < 100; ++i)
        y.emplace_back(evts[start + i]);

    plt::figure_size(1200, 500);
    plt::xlabel("Time (100ms)");
    plt::ylabel("Events number");
    plt::plot(y);
    if (argc > 2) {
        plt::save(argv[2]);
    } else {
        plt::save("data.png");
    }
    return 0;
}