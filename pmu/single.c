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

int main(void)
{
	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	
	attr.type = PERF_TYPE_HARDWARE;
	
	attr.config = PERF_COUNT_HW_INSTRUCTIONS;

	attr.disabled = 1;

	int fd = perf_event_open(&attr, 560978, -1, -1, 0);
	if(fd<0)
	{
		perror("Cannot open perf fd!");
		return 1;
	}

	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	while(1) {
		uint64_t instructions;

		read(fd, &instructions, sizeof(instructions));

		ioctl(fd, PERF_EVENT_IOC_RESET, 0);

		printf("intructions = %ld\n",instructions);
		sleep(1);
	}


}
