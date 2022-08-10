#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <linux/perf_event.h>

int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

struct read_format
{
	uint64_t nr;
	uint64_t values[2];
};

int main(void)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	
	attr.type = PERF_TYPE_HARDWARE;
	
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;

	attr.disabled = 1;

	attr.read_format = PERF_FORMAT_GROUP;

	int fd = perf_event_open(&attr, 0, -1, -1, 0);
	if(fd<0)
	{
		perror("Cannot open perf fd!");
		return 1;
	}


	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);

	attr.type = PERF_TYPE_HARDWARE;

	attr.config = PERF_COUNT_HW_CPU_CYCLES;

	attr.disabled = 1;

	int fd2 = perf_event_open(&attr , 0, -1, fd, 0);

	if(fd2<0){
		perror("Cannot open perf fd2");
		return 1;
	}



	ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
	while(1) {
		struct read_format aread;

		read(fd, &aread, sizeof(struct read_format));

		ioctl(fd, PERF_EVENT_IOC_RESET, 0);

		printf("intructions = %ld , cycles = %ld\n",aread.values[0],aread.values[1]);
		sleep(1);
	}


}
