MODULE := nodrop
TARGET := monitor

CC := /usr/bin/gcc-8
LD := /usr/bin/gcc-8
STRIP := /usr/bin/strip

INCLUDE_PATH += -I. -I../include
SPECS := -specs ./musl.specs
CFLAGS_ALL := $(INCLUDE_PATH) $(CFLAGS) -std=gnu11 -fPIE -fno-stack-protector
LDFLAGS_ALL := $(LDFLAGS) --static-pie -Wl,-Tscript_x86-64.ld $(SPECS)

TABLES_DIR = ../src/tables
MALLOC_DIR = malloc
SRC_DIRS = $(addprefix ./, src $(MALLOC_DIR))
BASE_GLOBS = $(addsuffix /*.c, $(SRC_DIRS))
TABLES_GLOBS = $(addsuffix /*.c, $(TABLES_DIR))
BASE_SRCS = $(sort $(wildcard $(BASE_GLOBS)))
TABLES_SRCS = $(sort $(wildcard $(TABLES_GLOBS)))
BASE_OBJS = $(patsubst ./%, %.o, $(basename $(BASE_SRCS)))
TABLES_OBJS = $(patsubst ../src/%, %.o, $(basename $(TABLES_SRCS)))
ALL_OBJS = $(addprefix obj/, $(sort $(BASE_OBJS) $(TABLES_OBJS)))

OBJ_DIRS = $(sort $(patsubst %/,%,$(dir $(ALL_OBJS))))

all: random $(TARGET)
	@rm _random.h

$(ALL_OBJS) : | $(OBJ_DIRS)

$(OBJ_DIRS):
	mkdir -p $@

$(TARGET): $(ALL_OBJS) 
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	$(LD) $^ -o $@ $(LDFLAGS_ALL)
	$(STRIP) -R .symtab $@ -o $@

obj/$(MALLOC_DIR)/%.o: ./$(MALLOC_DIR)/%.c
	$(CC) -c -I$(MALLOC_DIR)/include $(CFLAGS_ALL) $< -o $@
obj/%.o: ../src/%.c
	$(CC) -c $(CFLAGS_ALL) $< -o $@
obj/%.o: %.c
	$(CC) -c $(CFLAGS_ALL) $< -o $@


.PHONY: clean all random
random:
	@/bin/sh -c ./randgen.sh > _$@.h
clean:
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	rm -rf $(TARGET) $(OBJ_DIRS)
