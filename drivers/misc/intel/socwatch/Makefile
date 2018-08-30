ccflags-y := -I$(src)/include -I$(src)/inc
ccflags-y += -Werror=strict-prototypes
ccflags-y += -Werror=pointer-to-int-cast
ccflags-y += -Werror=int-to-pointer-cast
ccflags-y += -Werror=format
ccflags-y += -Werror=attributes


ccflags-y += -DDO_ANDROID=$(CONFIG_SOCWATCH_DO_ANDROID)
ccflags-y += -DDO_SOCPERF=$(CONFIG_SOCWATCH_DO_SOCPERF)
ccflags-y += -DDO_DRIVER_PROFILING=$(CONFIG_SOCWATCH_DO_PROFILING)


ifdef CONFIG_SOCWATCH_DO_DEBUG
	ccflags-y += -Werror
endif

obj-$(CONFIG_INTEL_SOCWATCH)	+= socwatch2_6.o

socwatch2_6-y	:=	sw_driver.o        \
			sw_hardware_io.o \
			sw_output_buffer.o \
			sw_tracepoint_handlers.o \
			sw_collector.o \
			sw_mem.o \
			sw_internal.o \
			sw_file_ops.o \
			sw_ops_provider.o \
			sw_trace_notifier_provider.o \
			sw_reader.o \
			sw_telem.o

