TARGET := gui

TABLES_DIR = ../src/tables
SRC_DIRS = .
IMGUI_DIR = ./imgui

BASE_GLOBS = $(addsuffix /*.cpp, $(SRC_DIRS))
IMGUI_GLOBS = $(addsuffix /*.cpp, $(IMGUI_DIR))
TABLES_GLOBS = $(addsuffix /*.c, $(TABLES_DIR))

BASE_SRCS = $(sort $(wildcard $(BASE_GLOBS)))
IMGUI_SRCS = $(sort $(wildcard $(IMGUI_GLOBS)))
TABLES_SRCS = $(sort $(wildcard $(TABLES_GLOBS)))

# $(info info: $(basename $(IMGUI_SRCS)))

BASE_OBJS = $(patsubst ./%, %.o, $(basename $(BASE_SRCS)))
IMGUI_OBJS = $(patsubst ./%, %.o, $(basename $(IMGUI_SRCS)))
TABLES_OBJS = $(patsubst ../src/%, %.o, $(basename $(TABLES_SRCS)))
ALL_OBJS = $(addprefix obj/, $(sort $(BASE_OBJS) $(IMGUI_OBJS) $(TABLES_OBJS)))

OBJ_DIRS = $(sort $(patsubst %/, %, $(dir $(ALL_OBJS))))

INCLUDE_PATH := -I. -I../include -I./imgui
CFLAGS += -fPIC $(INCLUDE_PATH)
CPPFLAGS += -fPIC -std=c++11 $(INCLUDE_PATH)
LDFLAGS += -lglfw -ldl -lGL #-lfreetype

all: $(TARGET)

$(TARGET): $(ALL_OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

# $(info info: $(ALL_OBJS))

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