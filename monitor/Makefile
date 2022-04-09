MODULE := nodrop
TARGET := monitor

VPATH := ../src

PRIM_C_FILES := main.c\
				events_table.c\
				flags_table.c\
				dynamic_params_table.c\

C_FILES := $(PRIM_C_FILES) context.c
S_FILES := misc.S

INCLUDE_PATH := -I. -I../include
CFLAGS := $(INCLUDE_PATH) -std=gnu11 -fPIE -g -Ofast -fno-stack-protector
LDFLAGS := -nostartfiles -Wl,-znow -pie #-Wl,-Tscript_x86-64.ld

O_FILES := $(patsubst %.c,%.o,$(notdir $(C_FILES))) 
O_FILES += $(patsubst %.S,%.o,$(notdir $(S_FILES)))

all: $(TARGET)

monitor: $(O_FILES)
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.S
	$(CC) $< -c $(CFLAGS) -o $@ $(LDFLAGS)
%.o: %.c
	$(CC) $< -c $(CFLAGS) -o $@ $(LDFLAGS)

.PHONY: clean all
clean:
	sudo rmmod -f $(MODULE) 2> /dev/null || true
	rm -f $(TARGET) $(O_FILES)
