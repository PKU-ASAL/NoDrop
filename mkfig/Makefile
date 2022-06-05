TARGET := draw

CPP_FILES := draw.cpp
C_FILES := events_table.c flags_table.c dynamic_params_table.c
CO_FILES := $(patsubst %.c,%.o,$(notdir ${C_FILES})) 
CPPO_FILES := $(patsubst %.cpp,%.o,$(notdir ${CPP_FILES}))
O_FILES := $(CO_FILES) $(CPPO_FILES)

TABLES_DIR = ../src/tables
SRC_DIRS = .
BASE_GLOBS = $(addsuffix /*.c, $(SRC_DIRS)) $(addsuffix /*.cpp, $(SRC_DIRS))
TABLES_GLOBS = $(addsuffix /*.c, $(TABLES_DIR))
BASE_SRCS = $(sort $(wildcard $(BASE_GLOBS)))
TABLES_SRCS = $(sort $(wildcard $(TABLES_GLOBS)))
BASE_OBJS = $(patsubst ./%, %.o, $(basename $(BASE_SRCS)))
TABLES_OBJS = $(patsubst ../src/%, %.o, $(basename $(TABLES_SRCS)))
ALL_OBJS = $(addprefix obj/, $(sort $(BASE_OBJS) $(TABLES_OBJS)))

OBJ_DIRS = $(sort $(patsubst %/,%,$(dir $(ALL_OBJS))))

PYCONF ?= /usr/bin/python3-config
ifneq ($(shell $(PYCONF) > /dev/null 2>&1; echo $$?), 1)
$(error "no installation of PYTHON3 found")
endif

PYTHON_CFLAGS := $(shell $(PYCONF) --cflags)
PYTHON_LDFLAGS := $(shell $(PYCONF) --ldflags)
INCLUDE_PATH := -I. -I../include
CFLAGS += -fPIC $(INCLUDE_PATH) $(PYTHON_CFLAGS)
CPPFLAGS += -fPIC -std=c++11 $(INCLUDE_PATH) $(PYTHON_CFLAGS)
LDFLAGS += -fpic $(PYTHON_LDFLAGS)

all: $(TARGET)

$(TARGET): $(ALL_OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

$(ALL_OBJS) : | $(OBJ_DIRS)

$(OBJ_DIRS):
	mkdir -p $@

obj/%.o: ../src/%.c
	$(CC) $< -c $(CFLAGS) -o $@
obj/%.o: %.c
	$(CC) $< -c $(CFLAGS) -o $@
obj/%.o: %.cpp
	$(CXX) $< -c $(CPPFLAGS) -o $@

.PHONY: clean all
clean:
	rm -rf $(TARGET) $(OBJ_DIRS)