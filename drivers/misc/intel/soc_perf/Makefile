ccflags-y := -I$(src)/include -I$(src)/inc

# TODO: verify chrome OS
#ccflags-y += -DDRV_CHROMEOS -Wno-error

obj-$(CONFIG_INTEL_SOCPERF) += socperf2_0.o

socperf2_0-y :=	socperfdrv.o	\
		control.o	\
		utility.o	\
		pci.o		\
		soc_uncore.o	\
		haswellunc_sa.o	\
		npk_uncore.o

